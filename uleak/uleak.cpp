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

// TODO: для 64-х бит необходимо точки хранить наверное в виде указателя.
// HINT: А можно в заголовке блока cp вообще не хранить, а хранить только
//	индекс в таблице точек вызова. И для пустых блоков тоже его сохранять.
//	Это освободит одно поле и унифицирует заголовок блока.
//	Собственно индекс у нас - 12 бит, признак занятости блока - это один бит.
//	Туда же можно будет впихнуть класс операции,
// HINT: Класс операции можно хранить в описании точки вызова. Он не меняется в
//	процессе работы. Хотя если я буду подниматься по иерархии - это может
//	быть несправедливо.

namespace {

// Частота вызова переодических операций.
// Меряется количествами вызовов функций alloc/free
const uint32_t operation_period = 10000;

// Ругаться на free(0)
const bool free_zero = false;

// Заполнение освобождаемых блоков и контроль использования после освобождения (может производиться с большо-о-ой задержкой)
const bool check_free = false;
const bool check_free_repetition = false;

// Контролировать пространство за пределами блока
const bool check_tail = true;
const bool check_tail_repetition = false;
// Размер буферной зоны
const uint32_t tail_zone = check_tail ? 32 : 0;

// Фильтровать стандартные функции из CallPoint's
const bool function_filter = false;

// размер хипа.
const uint32_t heap_size = 64 * 1024 * 1024;

// количество точек вызова. Их должно хватать. если не хватает будет assert.
const int call_points = 8192;
BOOST_STATIC_ASSERT(call_points <= (1 << 16));

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
	uint8_t used;

	uint32_t cp;
	uint32_t oldcp;
	uint32_t reserved[3];
} __attribute__((packed));

// Потом сокращу до 16
BOOST_STATIC_ASSERT(sizeof(struct block_control) == 32);

bool isActive = false;

uint8_t sheap[heap_size];

// -----------------------------------------------------------------------------
// Фильтрация стандартный функций из стека вызова.
// Было бы удобнее, если бы я мог получить имя функции по адресу.
// Я не знаю как это сделать.

const char *getCallPonitName(uint32_t cp, char *buf = 0, size_t size = 0)
{
	assert ((buf != 0 && size != 0) || (buf == 0 && size == 0));

	static char sym[80];
	char *symbuf = (buf != 0) ? buf : sym;
	size_t ss = (buf != 0) ? size : 80;

#ifdef LIBUNWIND
	// libunwind несколько ограничен в этом плане тем, что может показывать
	// символы толоько по курсору, который образуется только при обработке
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

		if (cp >= info.start_ip && cp < info.end_ip) {
			unw_get_proc_name (&cursor, symbuf, ss, 0);

			if (cp - info.start_ip > 0) {
				char off[12];
				snprintf (off, 12, "+0x%x", cp - info.start_ip);

				if (strlen(symbuf) + strlen(off) + 4 > ss) {
					strcpy(symbuf + ss - strlen(off) - 4, "...");
				}

				strcat(symbuf, off);
			}

			return symbuf;
		}
	}
#endif

	// Это как фоллбек даже для libunwind.
	snprintf(symbuf, ss, "0x%08x", cp);
	return symbuf;
}

// -----------------------------------------------------------------------------
// менеджер точек вызова
namespace cpmgr {

struct callpoint_stat {
	uint32_t cp;
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

int scallpointalloc(const struct block_control *block)
{
	for (int i = 0; i < call_points; i++) {
		if (cparray[i].cp == block->cp || cparray[i].cp == 0) {
			cparray[i].current_blocks++;
			cparray[i].cp = block->cp;

			if (cparray[i].current_blocks > cparray[i].max_blocks) {
				cparray[i].max_blocks = cparray[i].current_blocks;

				printf ("\t*** leak %u from %s with %ssize %u\n",
					cparray[i].max_blocks, getCallPonitName(cparray[i].cp),
					cparray[i].size == block->size ? "" : "variable ", block->size);
			}

			cparray[i].size = block->size;
			return i;
		}
	}

	return -1;
}

void scallpointfree(const struct block_control *block, uint32_t cp)
{
	const int i = block->cp_idx;
	assert(i >= 0 && i < call_points);
	assert(cparray[i].cp == block->cp);

	if (cparray[i].current_blocks == 0) {
		char aname[80], fname[80];
		printf ("\t*** extra free for block size %u allocated from %s, free from %s\n",
			block->size, getCallPonitName(cparray[i].cp, aname, 80), getCallPonitName(cp, fname, 80));
	} else {
		cparray[i].current_blocks--;
	}
}

} // namespace cpmgr

// -----------------------------------------------------------------------------
// Проверка переполнений блока

void sblock_tail_init (struct block_control *block, uint8_t *bptr)
{
	memset (bptr + sizeof(struct block_control) + block->size, AFILL, block->asize - block->size);
}

void sblock_tail_check (struct block_control *block, uint8_t *bptr)
{
	// Проконтролируем хвост блока...
	int corrupted = 0;

	for (int i = block->asize - block->size - 1; i >= 0; i--) {
		if (bptr[sizeof(struct block_control) + block->size + i] != AFILL) {
			corrupted = i;
			break;
		}
	}

	if (corrupted > 0) {
		printf ("\t*** corrupted block tail, %u bytes, allocated from %s, size %u\n",
			corrupted, getCallPonitName(block->cp), block->size);
	}

	// Таких вещей быть не должно...
	assert (corrupted == 0);
}

void sblock_tail_check_all ()
{
	for (uint8_t *bptr = sheap; bptr < sheap + heap_size; ) {
		struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
		assert (block->asize % 16 == 0);

		if (block->cp != 0) {
			sblock_tail_check (block, bptr);
		}

		bptr += sizeof(struct block_control) + block->asize;
		assert (bptr <= sheap + heap_size);
	}
}

// -----------------------------------------------------------------------------
// Проверка содержимого свободных блоков.

void sblock_free_init (struct block_control *block, uint8_t *bptr)
{
	// Замусорим блок специально.
	memset (bptr + sizeof(struct block_control), FFILL, block->asize);
}

void sblock_free_check (struct block_control *block, uint8_t *bptr)
{
	if (block->oldcp == 0)	// Инициализационный блок.
		return;

	bool modify = false;

	for (uint32_t i = 0; i < block->asize; i++) {
		if (bptr[sizeof(struct block_control) + i] != FFILL) {
			modify = true;
		}
	}

	if (modify) {
		printf ("\t*** modifyed free block %p, allocated from %s with size %u\n",
			bptr + sizeof(struct block_control), getCallPonitName(block->oldcp), block->size);
	}

	assert (!modify);
}

void sblock_free_check_all ()
{
	for (uint8_t *bptr = sheap; bptr < sheap + heap_size; ) {
		struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
		assert (block->asize % 16 == 0);

		if (block->cp == 0) {
			sblock_free_check (block, bptr);
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
	block->cp = 0;
	block->oldcp = 0;
	block->asize = block->size = heap_size - sizeof(struct block_control);
	assert (block->asize % 16 == 0);

	if (check_free) {
		sblock_free_init(block, sheap);
	}

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

	if (check_tail_repetition) {
		sblock_tail_check_all();
	}

	if (check_free_repetition) {
		sblock_free_check_all();
	}
}

// -----------------------------------------------------------------------------
// Дефрагментация хипа.

void sdefrag ()
{
	uint32_t maxfree = 0;

	for (uint8_t *bptr = sheap; bptr < sheap + heap_size; ) {
		struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
		assert (block->asize % 16 == 0);

		if (block->cp == 0) {
			if (check_free) {
				sblock_free_check(block, bptr);
			}

			while (true) {
				uint8_t *nbptr = bptr + sizeof(struct block_control) + block->asize;
				if (nbptr >= sheap + heap_size) break;

				struct block_control *nblock = reinterpret_cast<struct block_control *>(nbptr);
				assert (nblock->asize % 16 == 0);
				if (nblock->cp != 0) break;

				if (check_free) {
					sblock_free_check (nblock, nbptr);
				}

				block->oldcp = 0;	// Мы его уже проверили.
				block->asize += sizeof(struct block_control) + nblock->asize;
				block->size = block->asize;
			}

			if (check_free) {
				sblock_free_init(block, bptr);
			}

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

// -----------------------------------------------------------------------------
class slock {
private:
	enum lock_state { UNLOCKED, LOCKED };

	static volatile lock_state m_lock;

public:
	slock() {
		while (__sync_lock_test_and_set(&m_lock, LOCKED) == LOCKED) { };
	}

	~slock() {
		__sync_lock_release(&m_lock);
	}
};

volatile slock::lock_state slock::m_lock = UNLOCKED;

// -----------------------------------------------------------------------------
// Очень простая реализация менеджера памяти

// TODO: Для ускорения работы менеджера необходимо ввести очереди блоков. Только
//	вместо ссылок в них можно хранить смещения относительно sheap. Это будет
//	удобнее в плане переносимости.

void *salloc_internal (size_t size, uint32_t cp, uint32_t aclass)
{
	const uint32_t asize = (size + tail_zone + 15) & ~15;

	for (uint8_t *bptr = sheap; bptr < sheap + heap_size; ) {
		assert ((uint32_t)bptr % 16 == 0);

		struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
		assert (block->asize % 16 == 0);

		if (block->cp == 0 && block->asize >= asize) {
			if (check_free) {
				sblock_free_check (block, bptr);
			}

			if (block->asize > sizeof(struct block_control) + asize) {
				// Отделяем для выделения блок с конца!
				struct block_control *nblock = block;

				nblock->asize -= sizeof(struct block_control) + asize;
				// А size и oldcp пусть остаются вообще старыми

				bptr += sizeof(struct block_control) + nblock->asize;
				block = reinterpret_cast<struct block_control *>(bptr);

				block->asize = block->size = asize;
			}

			block->oldcp = block->cp = cp;

			assert (size <= block->asize);
			block->size = size;

			block->aclass = aclass;

			if (check_tail) {
				sblock_tail_init (block, bptr);
			}

			// Зарегистрировать точку вызова среди call_points
			int cp_idx = cpmgr::scallpointalloc(block);
			assert (cp_idx >= 0 && cp_idx < call_points);
			block->cp_idx = cp_idx;

			// Собрать статистику.
			memory_used += block->size;
			if (memory_used > memory_max_used) {
				memory_max_used = memory_used;
			}

			return bptr + sizeof(struct block_control);
		}

		bptr += sizeof(struct block_control) + block->asize;
	}

	return 0;
}

void sfree_internal (void *ptr, uint32_t cp, uint32_t aclass)
{
	if (ptr < sheap || ptr >= sheap + heap_size) {
		if (ptr != 0 || free_zero) {
			printf ("\t*** free unknown block %p from %s\n", ptr, getCallPonitName(cp));
		}

		return;
	}

	uint8_t *bptr = reinterpret_cast<uint8_t *>(ptr) - sizeof (struct block_control);
	struct block_control *block = reinterpret_cast<struct block_control *>(bptr);

	if (block->cp == 0 || block->cp == FFILL32) {
		// Блок уже освобожден.
		printf ("\t*** double free block %p from %s\n", ptr, getCallPonitName(cp));
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
			allocf[block->aclass], getCallPonitName(block->cp, aname, 80),
			freef[aclass], getCallPonitName(cp, fname, 80));

		assert(block->aclass != aclass);
		return;
	}

	cpmgr::scallpointfree(block, cp);

	if (check_tail) {
		sblock_tail_check (block, bptr);
	}

	block->cp = 0;

	if (check_free) {
		sblock_free_init (block, bptr);
	}

	assert (memory_used >= block->size);
	// статистика.
	memory_used -= block->size;
}

// -----------------------------------------------------------------------------
// Интерфейсные функции обеспечивают блокировки и всякую фигню.
void *salloc (size_t size, uint32_t cp, uint32_t aclass)
{
	assert (size < heap_size);
	if (!isActive) sinit();
	slock lock;
	speriodic();

	void *ptr = salloc_internal (size, cp, aclass);
	if (ptr == 0) {
		// Дефрагментировать и попытаться снова.
		sdefrag ();
		ptr = salloc_internal (size, cp, aclass);

		if (ptr == 0) {
			printf ("\t*** No memory for alloc(%u), called from %s\n", size, getCallPonitName(cp));
		}

		assert (ptr != 0);
	}

	assert ((uint32_t)ptr % 16 == 0);
	return ptr;
}

void sfree (void *ptr, uint32_t cp, uint32_t aclass)
{
	assert (isActive);
	slock lock;
	speriodic();
	sfree_internal(ptr, cp, aclass);
}

uint32_t sblocksize(void *ptr)
{
	assert (isActive);
	slock lock;

	uint8_t *bptr = reinterpret_cast<uint8_t *>(ptr) - sizeof(struct block_control);
	struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
	assert (block->cp != 0);
	return block->size;
}

uint32_t sblockcount(uint32_t cp)
{
	if (!isActive) sinit();

	slock lock;

	// TODO: определить количество блоков в этой точке вызова.
	return 0;
}

// Неблокируемая функция, но ей необходимо знать размер блока.
void *srealloc (void *ptr, size_t size, uint32_t cp, uint32_t aclass)
{
	void *nptr = salloc (size, cp, aclass);

	if (nptr == 0) return 0;

	if (ptr != 0) {
		memcpy (nptr, ptr, min(size, sblocksize(ptr)));
	}

	sfree (ptr, cp, aclass);
	return nptr;
}

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

uint32_t getCallPoint()
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
	return ip;

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
	return reinterpret_cast<uint32_t>(getReturnAddress(1));
#endif
}

} // static namespace

// -----------------------------------------------------------------------------
// Заместители стандартных функций должны отслеживать точки из которых их вызывают

// libc
extern "C"
void *malloc (size_t size)
{
	const uint32_t cp = getCallPoint();
	return salloc (size, cp, CLASS_C);
}

extern "C"
void *calloc (size_t number, size_t size)
{
	const uint32_t cp = getCallPoint();
	void *ptr = salloc (number * size, cp, CLASS_C);
	// calloc возвращает чищенную память!
	memset (ptr, 0, number * size);
	return ptr;
}

extern "C"
void *realloc (void *ptr, size_t size)
{
	const uint32_t cp = getCallPoint();
	return srealloc(ptr, size, cp, CLASS_C);
}

extern "C"
void *reallocf (void *ptr, size_t size)
{
	const uint32_t cp = getCallPoint();

	void *nptr = srealloc(ptr, size, cp, CLASS_C);
	if (nptr == 0 && ptr != 0)
		sfree (ptr, cp, CLASS_C);

	return nptr;
}

extern "C"
void free (void *ptr)
{
	const uint32_t cp = getCallPoint();
	sfree (ptr, cp, CLASS_C);
}

extern "C"
char *strdup(const char *str)
{
	const uint32_t cp = getCallPoint();

	char *str2 = reinterpret_cast<char *>(salloc(strlen(str) + 1, cp, CLASS_C));
	strcpy (str2, str);
	return str2;
}

// с++ runtime.
void *operator new(size_t size)
{
	const uint32_t cp = getCallPoint();
	return salloc (size, cp, CLASS_NEW);
}

void operator delete (void *ptr) throw()
{
	const uint32_t cp = getCallPoint();
	sfree (ptr, cp, CLASS_NEW);
}

void *operator new[] (unsigned int size)
{
	const uint32_t cp = getCallPoint();
	return salloc (size, cp, CLASS_NEW_ARRAY);
}

void operator delete[] (void *ptr) throw()
{
	const uint32_t cp = getCallPoint();
	sfree (ptr, cp, CLASS_NEW_ARRAY);
}
