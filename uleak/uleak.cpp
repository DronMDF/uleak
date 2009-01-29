//
// Copyright (c) 2000-2008 Андрей Валяев (dron@infosec.ru)
// This code is licenced under the GPL3 (http://www.gnu.org/licenses/#GPL)
//

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>

#include <algorithm>

#include <boost/static_assert.hpp>

#ifdef LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#endif

using namespace std;

// TODO: Для ускорения работы менеджера необходимо ввести очереди блоков. Только
//	вместо ссылок в них можно хранить смещения относительно sheap. Это будет
//	удобнее в плане переносимости.


namespace {

// Частота вызова переодических операций.
// Меряется количествами вызовов функций alloc/free
const uint32_t operation_period = 10000;

// Ругаться на free(0)
const bool free_zero = false;

// Заполнение освобождаемых блоков и контроль использования после освобождения (может производиться с большо-о-ой задержкой)
const bool check_free = false;
const uint32_t check_free_limit = 1024;	// Максимально проверяемый размер блока
const bool check_free_repetition = false;

// Контролировать пространство за пределами блока
const bool check_tail = true;
const bool check_tail_repetition = false;
// Размер буферной зоны
const uint32_t tail_zone = check_tail ? 32 : 0;

// размер хипа.
const uint32_t heap_size = 64 * 1024 * 1024;

// количество точек вызова. Их должно хватать. если не хватает будет assert.
const int call_points = 8192;

// Допустимое количество блоков на точку. во избежание лишней ругани.
const uint32_t block_limit = 50000;

// Типы операторов освобождения должны соответствовать операторам выделения.
enum {
	CLASS_C = 0,
	CLASS_NEW = 1,
	CLASS_NEW_ARRAY = 2,
};

// -----------------------------------------------------------------------------

// Статистика использования памяти.
uint32_t memory_used = 0;
uint32_t memory_max_used = 0;

const uint8_t FFILL = 0xFB;
const uint32_t FFILL32 = 0xFBFBFBFB;
const uint8_t AFILL = 0xAB;

struct block_control {
	uint32_t asize;	// aligned size
	uint32_t size;
	uint16_t cp_idx;
	uint8_t aclass;	// класс операций памяти
	uint8_t flags;

	uint32_t cp __attribute__((deprecated));

	uint8_t ptr[0];
} __attribute__((packed));

enum {
	BF_USED = 0x0001,

};

// Потом сокращу до 16
BOOST_STATIC_ASSERT(sizeof(struct block_control) == 16);
BOOST_STATIC_ASSERT(call_points < 0x7fff);

bool isActive = false;

uint8_t sheap[heap_size];

typedef const void *callpoint_t;

// -----------------------------------------------------------------------------

const char *getCallPonitName(callpoint_t cp, char *buf, size_t bufsz)
{
	assert (buf != 0 && bufsz != 0);

	memset(buf, 0, bufsz);	// Паранойя?
#ifdef LIBUNWIND
	// libunwind несколько ограничен в этом плане тем, что может показывать
	// символы только по курсору, который образуется только при обработке
	// стека вызовов... возможны ситуации, когда адрес выделения не будет
	// отображаться как имя.
	unw_context_t uc;
	unw_getcontext(&uc);

	unw_cursor_t cursor;
	unw_init_local(&cursor, &uc);

	while (unw_step(&cursor) > 0) {
		unw_proc_info_t info;
		unw_get_proc_info(&cursor, &info);
		if (info.start_ip == 0 || info.end_ip == 0)
			continue;

		const unw_word_t cpr = reinterpret_cast<unw_word_t>(cp);

		if (cpr >= info.start_ip && cpr < info.end_ip) {
			int rv = unw_get_proc_name (&cursor, buf, bufsz, 0);
			if (rv == UNW_EUNSPEC || rv == UNW_ENOINFO || strlen(buf) == 0) {
				// Имя процедуры не обнаруживается.
				snprintf (buf, bufsz, "%p", reinterpret_cast<callpoint_t>(info.start_ip));
			}

			if (cpr - info.start_ip > 0) {
				char off[12];
				snprintf (off, 12, "+0x%lx", (unsigned long)(cpr - info.start_ip));

				if (strlen(buf) + strlen(off) + 4 > bufsz) {
					strcpy(buf + bufsz - strlen(off) - 4, "...");
				}

				strcat(buf, off);
			}

			return buf;
		}
	}
#endif

	// Это как фоллбек даже для libunwind.
	snprintf(buf, bufsz, "%p", cp);
	return buf;
}

// -----------------------------------------------------------------------------
namespace cpmgr {
// менеджер точек вызова

struct callpoint_stat {
	callpoint_t cp;
	uint32_t current_blocks;
	uint32_t max_blocks;
	uint32_t size;
};

struct callpoint_stat cparray[call_points];

void init()
{
	for (int i = 0; i < call_points; i++) {
		cparray[i].cp = 0;
		cparray[i].size = 0;
		cparray[i].current_blocks = 0;
		cparray[i].max_blocks = block_limit;
	}
}

int scallpointalloc(const struct block_control *block, callpoint_t cp)
{
	for (int i = 0; i < call_points; i++) {
		if (cparray[i].cp == cp || cparray[i].cp == 0) {
			cparray[i].current_blocks++;
			cparray[i].cp = cp;

			if (cparray[i].current_blocks > cparray[i].max_blocks) {
				cparray[i].max_blocks = cparray[i].current_blocks;

				char name[80];
				printf ("\t*** leak %u from %s with %ssize %u\n",
					cparray[i].max_blocks, getCallPonitName(cparray[i].cp, name, 80),
					cparray[i].size == block->size ? "" : "variable ", block->size);
			}

			cparray[i].size = block->size;
			return i;
		}
	}

	assert(!"Not avail call point");
	return -1;
}

void scallpointfree(const struct block_control *block, callpoint_t cp)
{
	const int i = block->cp_idx;
	assert(i >= 0 && i < call_points);

	if (cparray[i].current_blocks == 0) {
		char aname[80], fname[80];
		printf ("\t*** extra free for block size %u allocated from %s, free from %s\n",
			block->size, getCallPonitName(cparray[i].cp, aname, 80), getCallPonitName(cp, fname, 80));
	} else {
		cparray[i].current_blocks--;
	}
}

callpoint_t getCallPoint(int idx)
{
	assert (idx >= 0 && idx < call_points);
	return cparray[idx].cp;
}

} // namespace cpmgr

// -----------------------------------------------------------------------------
// Проверка переполнений блока

void sblock_tail_init (struct block_control *block)
{
	if (!check_tail) return;
	memset (block->ptr + block->size, AFILL, block->asize - block->size);
}

void sblock_tail_check (const struct block_control *block)
{
	if (!check_tail) return;

	for (int i = block->asize - block->size - 1; i >= 0; i--) {
		if (block->ptr[block->size + i] != AFILL) {
			char name[80];
			printf ("\t*** corrupted block tail, %u bytes, allocated from %s, size %u\n",
				i, getCallPonitName(cpmgr::getCallPoint(block->cp_idx), name, 80), block->size);
			assert(!"Corrupted block tail");
		}
	}

}

void sblock_tail_check_all ()
{
	if (!check_tail_repetition) return;

	for (uint8_t *bptr = sheap; bptr < sheap + heap_size; ) {
		struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
		assert (block->asize % 16 == 0);

		if ((block->flags & BF_USED) != 0) {
			sblock_tail_check (block);
		}

		bptr += sizeof(struct block_control) + block->asize;
		assert (bptr <= sheap + heap_size);
	}
}

// -----------------------------------------------------------------------------
// Проверка содержимого свободных блоков.

void sblock_free_init (struct block_control *block)
{
	if (!check_free) return;
	if (block->asize > check_free_limit) return;

	// Замусорим блок специально.
	memset (block->ptr, FFILL, block->asize);
}

void sblock_free_check (const struct block_control *block)
{
	if (!check_free) return;
	if (block->asize > check_free_limit) return;

	for (uint32_t i = 0; i < block->asize; i++) {
		if (block->ptr[i] != FFILL) {
			char name[80];
			printf ("\t*** modifyed free block %p, allocated from %s with size %u\n",
				block->ptr, getCallPonitName(cpmgr::getCallPoint(block->cp_idx), name, 80), block->size);
			assert(!"Corrupted free block");
		}
	}
}

void sblock_free_check_all ()
{
	if (!check_free_repetition) return;

	for (uint8_t *bptr = sheap; bptr < sheap + heap_size; ) {
		struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
		assert (block->asize % 16 == 0);

		if ((block->flags & BF_USED) == 0) {
			sblock_free_check (block);
		}

		bptr += sizeof(struct block_control) + block->asize;
		assert (bptr <= sheap + heap_size);
	}
}

// -----------------------------------------------------------------------------
// Инициализация.

void sinit()
{
	struct block_control *block = reinterpret_cast<struct block_control *>(sheap);
	block->asize = block->size = heap_size - sizeof(struct block_control);
	block->flags = 0;
	assert (block->asize % 16 == 0);

	sblock_free_init(block);

	cpmgr::init();

	// Для корректного вывода.
	setvbuf(stdout, NULL, _IONBF, 0);

	isActive = true;
}

// -----------------------------------------------------------------------------
// Переодические операции (статистика по памяти по любому плюс опциональные вещи)

void speriodic()
{
	// Счетчик выделений. Для отображения статистики памяти.
	static uint32_t scounter = 0;

	scounter++;
	if (scounter % operation_period != 0)
		return;

	// Статистика использования памяти.
	printf ("\t*** Heap used: %u, max: %u\n", memory_used, memory_max_used);

	sblock_tail_check_all();
	sblock_free_check_all();
}

// -----------------------------------------------------------------------------
// Очень простая реализация менеджера памяти

namespace heapmgr {

void *alloc (size_t size, callpoint_t cp, uint32_t aclass)
{
	if (size == 0) {
		char name[80];
		printf ("\t*** zero size alloc from %s\n",
			getCallPonitName(cp, name, 80));
	}

	const uint32_t asize = (size + tail_zone + 15) & ~15;

	for (uint8_t *bptr = sheap; bptr < sheap + heap_size; ) {
		assert ((unsigned long)bptr % 16 == 0);

		struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
		assert (block->asize % 16 == 0);

		if ((block->flags & BF_USED) == 0 && block->asize >= asize) {
			sblock_free_check (block);

			if (block->asize > sizeof(struct block_control) + asize) {
				// Отделяем для выделения блок с конца!
				struct block_control *nblock = block;

				nblock->asize -= sizeof(struct block_control) + asize;
				// А size и oldcp пусть остаются вообще старыми

				bptr += sizeof(struct block_control) + nblock->asize;
				block = reinterpret_cast<struct block_control *>(bptr);

				block->asize = block->size = asize;
			}

			block->flags |= BF_USED;

			assert (size <= block->asize);
			block->size = size;
			block->aclass = aclass;

			sblock_tail_init (block);

			block->cp_idx = cpmgr::scallpointalloc(block, cp);

			// Собрать статистику.
			memory_used += block->size;
			if (memory_used > memory_max_used) {
				memory_max_used = memory_used;
			}

			return block->ptr;
		}

		bptr += sizeof(struct block_control) + block->asize;
	}

	return 0;
}

void free (void *ptr, callpoint_t cp, uint32_t aclass)
{
	if (ptr < sheap || ptr >= sheap + heap_size) {
		if (ptr != 0 || free_zero) {
			char name[80];
			printf ("\t*** free unknown block %p from %s\n",
				ptr, getCallPonitName(cp, name, 80));
		}

		return;
	}

	uint8_t *bptr = reinterpret_cast<uint8_t *>(ptr) - sizeof (struct block_control);
	struct block_control *block = reinterpret_cast<struct block_control *>(bptr);

	if ((block->flags & BF_USED) == 0) {
		for (uint8_t *fptr = sheap; fptr < sheap + heap_size; ) {
			struct block_control *fblock = reinterpret_cast<struct block_control *>(fptr);
			assert (fblock->asize % 16 == 0);

			if (fblock == block) {
				// Блок уже освобожден.
				char name[80];
				printf ("\t*** double free block %p from %s\n",
					ptr, getCallPonitName(cp, name, 80));
				return;
			}

			fptr += sizeof(struct block_control) + fblock->asize;
			assert (fptr <= sheap + heap_size);
		}

		// Кривой указатель или блок освобожден уже слишком давно.
		char name[80];
		printf ("\t*** invalid pointer for free block %p from %s\n",
			ptr, getCallPonitName(cp, name, 80));
		return;
	}

	if (block->aclass != aclass) {
		assert (block->aclass < 3);
		assert (aclass < 3);

		const char *allocf[] = {"*alloc", "new", "new[]"};
		const char *freef[] = {"free", "delete", "delete[]"};

		//  Нарушение класса функций
		char aname[80], fname[80];
		printf ("\t*** block allocated over '%s' from %s, free over '%s' from %s\n",
			allocf[block->aclass], getCallPonitName(cpmgr::getCallPoint(block->cp_idx), aname, 80),
			freef[aclass], getCallPonitName(cp, fname, 80));
		assert(!"Mismatch function class");
	}

	cpmgr::scallpointfree(block, cp);
	sblock_tail_check (block);
	block->flags = 0;
	sblock_free_init (block);

	assert (memory_used >= block->size);
	// статистика.
	memory_used -= block->size;
}

void defrag ()
{
	uint32_t maxfree = 0;

	for (uint8_t *bptr = sheap; bptr < sheap + heap_size; ) {
		struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
		assert (block->asize % 16 == 0);

		if ((block->flags & BF_USED) == 0) {
			sblock_free_check(block);

			while (true) {
				uint8_t *nbptr = block->ptr + block->asize;
				if (nbptr >= sheap + heap_size) break;

				struct block_control *nblock = reinterpret_cast<struct block_control *>(nbptr);
				assert (nblock->asize % 16 == 0);
				if ((nblock->flags & BF_USED) != 0) break;

				sblock_free_check (nblock);

				block->asize += sizeof(struct block_control) + nblock->asize;
				block->size = block->asize;
			}

			sblock_free_init(block);

			if (block->asize > maxfree) {
				maxfree = block->asize;
			}
		}

		// Накладные расходы складываются из заголовков блоков.
		bptr += sizeof(struct block_control) + block->asize;
		assert (bptr <= sheap + heap_size);
	}

	printf ("\t*** defrag. max free block - %u\n", maxfree);
	speriodic();
}

} // namespace heapmgr

// -----------------------------------------------------------------------------
// Интерфейсные функции обеспечивают блокировки и всякую фигню.
namespace heapif {

class lock_t {
private:
	enum lock_state { UNLOCKED, LOCKED };

	static volatile lock_state m_lock;

public:
	lock_t() {
		while (__sync_lock_test_and_set(&m_lock, LOCKED) == LOCKED) { };
	}

	~lock_t() {
		__sync_lock_release(&m_lock);
	}
};

volatile lock_t::lock_state lock_t::m_lock = UNLOCKED;

void *alloc (size_t size, callpoint_t cp, uint32_t aclass)
{
	assert (size < heap_size);
	if (!isActive) sinit();
	lock_t lock;
	speriodic();

	void *ptr = heapmgr::alloc(size, cp, aclass);
	if (ptr == 0) {
		// Дефрагментировать и попытаться снова.
		heapmgr::defrag();
		ptr = heapmgr::alloc(size, cp, aclass);

		if (ptr == 0) {
			char name[80];
			printf("\t*** No memory for alloc(%u), called from %s\n",
				uint32_t(size), getCallPonitName(cp, name, 80));
			assert(!"No memory");
		}
	}

	assert ((unsigned long)ptr % 16 == 0);
	return ptr;
}

void free (void *ptr, callpoint_t cp, uint32_t aclass)
{
	assert(isActive);
	lock_t lock;
	speriodic();
	heapmgr::free(ptr, cp, aclass);
}

uint32_t blocksize(void *ptr)
{
	assert(isActive);
	lock_t lock;

	uint8_t *bptr = reinterpret_cast<uint8_t *>(ptr) - sizeof(struct block_control);
	struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
	return block->size;
}

uint32_t blockcount(callpoint_t cp)
{
	if (!isActive) sinit();
	lock_t lock;

	// TODO: определить количество блоков в этой точке вызова.
	return 0;
}

// Неблокируемая функция, но ей необходимо знать размер блока.
void *realloc (void *ptr, size_t size, callpoint_t cp, uint32_t aclass)
{
	void *nptr = alloc(size, cp, aclass);

	if (nptr == 0) return 0;

	if (ptr != 0) {
		memcpy(nptr, ptr, min(uint32_t(size), blocksize(ptr)));
	}

	free (ptr, cp, aclass);
	return nptr;
}

} // namespace heapif

// -----------------------------------------------------------------------------
// Определение точек вызова

#ifndef LIBUNWIND
void *getReturnAddress (int level)
{
	switch (level) {
		case 0: return __builtin_return_address(0);
		case 1: return __builtin_return_address(1);
		case 2: return __builtin_return_address(2);
		case 3: return __builtin_return_address(3);
		case 4: return __builtin_return_address(4);
		case 5: return __builtin_return_address(5);
		case 6: return __builtin_return_address(6);
		case 7: return __builtin_return_address(7);
		case 8: return __builtin_return_address(8);
		case 9: return __builtin_return_address(9);
		case 10: return __builtin_return_address(10);
		case 11: return __builtin_return_address(11);
		case 12: return __builtin_return_address(12);
		case 13: return __builtin_return_address(13);
		case 14: return __builtin_return_address(14);
		case 15: return __builtin_return_address(15);
		case 16: return __builtin_return_address(16);
		case 17: return __builtin_return_address(17);
		case 18: return __builtin_return_address(18);
		case 19: return __builtin_return_address(19);
		default: break;
	}

	return 0;
}
#endif

callpoint_t getCallPoint()
{
#ifdef LIBUNWIND
	// Релизация на libunwind, пока не проверена.
	unw_context_t uc;
	unw_getcontext(&uc);

	unw_cursor_t cursor;
	unw_init_local(&cursor, &uc);

	// Сразу выходим за пределы модуля.
	unw_step(&cursor);
	unw_step(&cursor);

	unw_word_t ip;
	unw_get_reg(&cursor, UNW_REG_IP, &ip);
	return reinterpret_cast<callpoint_t>(ip);

// 	while (unw_step(&cursor) > 0) {
// 		char sym[80];
// 		unw_get_proc_name(&cursor, sym, 80, 0);
//
// 		// Что-то это далеко не полный список...
// 		if (	strncmp(sym, "_ZNS", 4) == 0 ||		// std::
// 			strncmp(sym, "_ZN5boost", 9) == 0)	// boost::
// 		{
// 			continue;
// 		}
//
// 		// В случае переполнения счетчика точки -
// 		// переходим на верхний уровень.
// 		unw_word_t ip;
// 		unw_get_reg(&cursor, UNW_REG_IP, &ip);
// 		if (getBlockCount(ip) < block_limit)
// 			return ip;
// 	}
#else
	return reinterpret_cast<callpoint_t>(getReturnAddress(1));
#endif
}

} // static namespace

// -----------------------------------------------------------------------------
// Заместители стандартных функций должны отслеживать точки из которых их вызывают

// libc
extern "C"
void *malloc (size_t size)
{
	const callpoint_t cp = getCallPoint();
	return heapif::alloc(size, cp, CLASS_C);
}

extern "C"
void *calloc (size_t number, size_t size)
{
	const callpoint_t cp = getCallPoint();
	void *ptr = heapif::alloc(number * size, cp, CLASS_C);
	// calloc возвращает чищенную память!
	memset(ptr, 0, number * size);
	return ptr;
}

extern "C"
void *realloc (void *ptr, size_t size)
{
	const callpoint_t cp = getCallPoint();
	return heapif::realloc(ptr, size, cp, CLASS_C);
}

extern "C"
void *reallocf (void *ptr, size_t size)
{
	const callpoint_t cp = getCallPoint();

	void *nptr = heapif::realloc(ptr, size, cp, CLASS_C);
	if (nptr == 0 && ptr != 0) {
		heapif::free(ptr, cp, CLASS_C);
	}

	return nptr;
}

extern "C"
void free (void *ptr)
{
	const callpoint_t cp = getCallPoint();
	heapif::free (ptr, cp, CLASS_C);
}

extern "C"
char *strdup(const char *str)
{
	const callpoint_t cp = getCallPoint();

	char *str2 = reinterpret_cast<char *>(heapif::alloc(strlen(str) + 1, cp, CLASS_C));
	strcpy (str2, str);
	return str2;
}

// с++ runtime.
void *operator new(size_t size)
{
	const callpoint_t cp = getCallPoint();
	return heapif::alloc(size, cp, CLASS_NEW);
}

void operator delete (void *ptr) throw()
{
	const callpoint_t cp = getCallPoint();
	heapif::free(ptr, cp, CLASS_NEW);
}

void *operator new[] (size_t size)
{
	const callpoint_t cp = getCallPoint();
	return heapif::alloc (size, cp, CLASS_NEW_ARRAY);
}

void operator delete[] (void *ptr) throw()
{
	const callpoint_t cp = getCallPoint();
	heapif::free(ptr, cp, CLASS_NEW_ARRAY);
}
