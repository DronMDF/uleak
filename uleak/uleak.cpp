//
// Copyright (c) 2000-2008 Андрей Валяев (dron@infosec.ru)
// This code is licenced under the GPL3 (http://www.gnu.org/licenses/#GPL)
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <algorithm>

#include <boost/static_assert.hpp>
#define BOOST_ENABLE_ASSERT_HANDLER
#include <boost/assert.hpp>

#ifdef LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#endif

using namespace std;

// TODO: Для ускорения работы менеджера необходимо ввести очереди блоков.
// В 16-байтном заголовке блока места хватает и на указатель, если учесть что
// size используется только для занятых блоков.

namespace boost {
void assertion_failed (char const * expr, char const * function, char const * file, long line)
{
	// Не используем ничего кроме printf.
	printf ("%s:%lu: assertion failed '%s'\n", file, line, expr);
	printf ("%s:%lu: from %s\n", file, line, function);

	abort();
}
} // namespace boost

namespace {

// Частота вызова переодических операций.
// Меряется количествами вызовов функций alloc/free
const uint32_t operation_period = 10000;

// Ругаться на free(0)
const bool free_zero = false;

// Заполнение освобождаемых блоков и контроль использования после освобождения (может производиться с большо-о-ой задержкой)
const bool check_free = true;
const uint32_t check_free_limit = 256;	// Максимально проверяемый размер блока
const bool check_free_repetition = true;

// Хранить свободные блоки по возможности дольше. (замедляет работу в ~60 раз)
const bool keep_free = false;

// Контролировать пространство за пределами блока
const bool check_tail = true;
const bool check_tail_repetition = true;
// Размер буферной зоны
const uint32_t tail_zone = check_tail ? 32 : 0;

// голова блока, пока просто выделим не проверяя содержимого.
const uint32_t head_zone = 16;

// размер хипа.
const uint32_t heap_size = 256 * 1024 * 1024;

// количество точек вызова. Их должно хватать. если не хватает будет BOOST_ASSERT.
const int call_points = 8192;

// Допустимое количество блоков на точку. во избежание лишней ругани.
const uint32_t block_limit = 20000;

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
const uint8_t AFILL = 0xAB;

struct block_control {
	uint32_t asize;	// aligned size
	int16_t cp_idx;
	uint8_t aclass;	// класс операций памяти
	uint8_t flags;

	union {
		uint32_t size;
		struct block_control *next;
		uint64_t reserved;	// Задает размер юнии
	};

	uint8_t ptr[0];
} __attribute__((packed));

enum {
	BF_USED = 0x0001,
	BF_FFILL = 0x0002,
};

BOOST_STATIC_ASSERT(sizeof(struct block_control) == 16);
BOOST_STATIC_ASSERT(call_points < 0x7fff);

typedef const void *callpoint_t;

uint8_t sheap[heap_size];

// -----------------------------------------------------------------------------

const char *getCallPonitName(callpoint_t cp, char *buf, size_t bufsz)
{
	BOOST_ASSERT (buf != 0 && bufsz != 0);

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

			// В связи со изменением стратегии обработки коллпоинтов
			// .max_blocks вообще теряет смысл.
			if (cparray[i].current_blocks > cparray[i].max_blocks) {
				cparray[i].max_blocks = cparray[i].current_blocks;
			}

			// В связи с изменением стратегии обработки коллпоинтов - ругаться надо заранее.
			if (cparray[i].current_blocks > block_limit * 9 / 10) {
				char name[80];
				printf ("\t*** leak %u from %s with %ssize %u\n",
					cparray[i].max_blocks, getCallPonitName(cparray[i].cp, name, 80),
					cparray[i].size == block->size ? "" : "variable ", block->size);
			}

			cparray[i].size = block->size;
			return i;
		}
	}

	BOOST_ASSERT(!"Not avail call point");
	return -1;
}

void scallpointfree(const struct block_control *block, callpoint_t cp)
{
	const int i = block->cp_idx;
	BOOST_ASSERT(i >= 0 && i < call_points);

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
	BOOST_ASSERT (idx >= 0 && idx < call_points);
	return cparray[idx].cp;
}

void result()
{
	// А вот здесь засада... она вызывается несколько раз в разных нитях
	// (может быть в разных модулях?)
	printf ("\t*** exited statistic:\n");
	for (int i = 0; i < call_points && cparray[i].cp != 0; i++) {
		if (cparray[i].current_blocks == 0) continue;

		// NOTE: Эта функция вызывается значительно позже всего, видимо
		// из за этого функция getCallPonitName крешится.
		printf ("\t*** memory leak %u blocks with size %u, allocated from %p.\n",
			cparray[i].current_blocks, cparray[i].size, cparray[i].cp);
	}
}

// Ее бы блочить конечно для порядку надо, она будет вызываться из getCallPoint.
// но она не меняет соджержимого так что пойдет и так.
bool AvailCallPoint(callpoint_t cp)
{
	for (int i = 0; i < call_points && cparray[i].cp != 0; i++) {
		if (cparray[i].cp == cp) {
			return (cparray[i].current_blocks < block_limit);
		}
	}

	return true;
}

} // namespace cpmgr

namespace heapmgr {

struct block_control * const begin_block =
	reinterpret_cast<struct block_control *>(sheap);
const struct block_control * const end_block =
	reinterpret_cast<struct block_control *>(sheap + heap_size);

// утилиты всякие...
struct block_control *nextblock(struct block_control *block)
{
	// Должен быть корректно установлен asize;
	return reinterpret_cast<struct block_control *>(block->ptr + block->asize);
}

struct block_control *getBlockByPtr(void *ptr)
{
	uint8_t *bptr = reinterpret_cast<uint8_t *>(ptr) - (sizeof (struct block_control) + head_zone);
	struct block_control *block = reinterpret_cast<struct block_control *>(bptr);

	if (block < begin_block || block >= end_block)
		return 0;

	return block;
}

// -----------------------------------------------------------------------------
// Проверка переполнений блока

void blocktail_init (struct block_control *block)
{
	BOOST_ASSERT ((block->flags & BF_USED) != 0);

	if (!check_tail) return;

	memset (block->ptr + head_zone + block->size, AFILL, block->asize - (head_zone + block->size));
}

void blocktail_check (const struct block_control *block)
{
	BOOST_ASSERT ((block->flags & BF_USED) != 0);

	if (!check_tail) return;

	const size_t tail_offset = block->size + head_zone;

	for (int i = block->asize - tail_offset - 1; i >= 0; i--) {
		if (block->ptr[tail_offset + i] != AFILL) {
			char name[80];
			printf ("\t*** corrupted block tail, %u bytes, allocated from %s, size %u\n",
				i, getCallPonitName(cpmgr::getCallPoint(block->cp_idx), name, 80), block->size);
			BOOST_ASSERT(!"Corrupted block tail");
		}
	}
}

void blocktail_check_all ()
{
	if (!check_tail_repetition) return;

	struct block_control *block = begin_block;
	while (block < end_block) {
		BOOST_ASSERT (block->asize % 16 == 0);

		if ((block->flags & BF_USED) != 0) {
			blocktail_check (block);
		}

		block = nextblock(block);
	}

	BOOST_ASSERT (block == end_block);
}

// -----------------------------------------------------------------------------
// Проверка содержимого свободных блоков.

void freeblock_init (struct block_control *block)
{
	BOOST_ASSERT ((block->flags & BF_USED) == 0);

	if (!check_free) return;
	if (block->asize > check_free_limit) return;

	// Замусорим блок специально.
	memset (block->ptr, FFILL, block->asize);
	block->flags |= BF_FFILL;
}

void freeblock_check (const struct block_control *block)
{
	BOOST_ASSERT ((block->flags & BF_USED) == 0);

	if (!check_free) return;
	if (block->asize > check_free_limit) return;

	BOOST_ASSERT ((block->flags & BF_FFILL) != 0);

	for (uint32_t i = 0; i < block->asize; i++) {
		if (block->ptr[i] != FFILL) {
			char name[80];
			printf ("\t*** modifyed free block %p, allocated from %s with size %u\n",
				block->ptr, getCallPonitName(cpmgr::getCallPoint(block->cp_idx), name, 80), block->asize);
			BOOST_ASSERT(!"Corrupted free block");
		}
	}
}

void freeblock_check_all ()
{
	if (!check_free_repetition) return;

	struct block_control *block = begin_block;
	while (block < end_block) {
		BOOST_ASSERT (block->asize % 16 == 0);

		if ((block->flags & BF_USED) == 0) {
			freeblock_check (block);
		}

		block = nextblock(block);
	}

	BOOST_ASSERT (block == end_block);
}

namespace cache {

// Кэш существует ради ускорения менеджера до приемлимых скоростей.

struct block_control *pcache[17];

void init()
{
	for (int i = 0; i < 17; i++) {
		pcache[i] = 0;
	}
}

void storeblock (struct block_control *block)
{
	BOOST_ASSERT ((block->flags & BF_USED) == 0);
	size_t bsize = block->asize - tail_zone - head_zone;

	int cidx = (bsize - 1) / 16;
	if (cidx > 15) cidx = 16;

	if (pcache[cidx] != 0 && keep_free) {
		// Добавляем блоки в конец цепочки.
		block->next = 0;
		struct block_control *cblock = pcache[cidx];
		while (cblock->next != 0)
			cblock = cblock->next;
		cblock->next = block;
	} else {
		block->next = pcache[cidx];
		pcache[cidx] = block;
	}
}

struct block_control *findblock(size_t asize)
{
	// Поиск блока по кешу.
	size_t bsize = asize - tail_zone - head_zone;
	int cidx = (bsize - 1) / 16;
	if (cidx > 15) cidx = 16;

	while (cidx < 17) {
		// Строки кеша до 16 не требуют перебора, все блоки в них одинаковы.
		// Но они вполне нормально прокатят по общему алгоритму.

		struct block_control **bptr = &(pcache[cidx]);
		while (*bptr != 0) {
			struct block_control *block = *bptr;
 			freeblock_check (block);

			if (block->asize >= asize) {
				// отлинковать
				*bptr = block->next;
				return block;
			}

			bptr = &(block->next);
		}

		cidx++;
	}

	return 0;

// 	// Здесь пока последовательный поиск, буду переделывать на индексированный
// 	struct block_control *block = begin_block;
// 	while (block < end_block) {
// 		BOOST_ASSERT (block->asize % 16 == 0);
//
// 		if ((block->flags & BF_USED) == 0 && block->asize >= asize) {
// 			freeblock_check (block);
// 			return block;
// 		}
//
// 		block = nextblock(block);
// 	}
//
// 	BOOST_ASSERT (block == end_block);
// 	return 0;
}

} // namespace cache

void init()
{
	cache::init();

	begin_block->asize = heap_size - sizeof(struct block_control);
	BOOST_ASSERT (begin_block->asize % 16 == 0);

	begin_block->flags = 0;
	begin_block->cp_idx = -1;

	freeblock_init(begin_block);
	cache::storeblock(begin_block);
}

void *alloc (size_t size, callpoint_t cp, uint32_t aclass)
{
	BOOST_ASSERT (aclass < 3);

	if (size == 0) {
		char name[80];
		printf ("\t*** zero size alloc from %s\n",
			getCallPonitName(cp, name, 80));
	}

	const uint32_t asize = (size + head_zone + tail_zone + 15) & ~15;

	struct block_control *block = cache::findblock(asize);
	if (block == 0) return 0;

	if (block->asize > asize + sizeof(struct block_control) + head_zone + tail_zone) {
		// Отделяем для выделения блок с конца!
		struct block_control *nblock = block;

		nblock->asize -= sizeof(struct block_control) + asize;

		block = nextblock(nblock);
		block->asize = asize;

		freeblock_init(nblock);
		cache::storeblock(nblock);
	}

	block->flags = BF_USED;

	BOOST_ASSERT (size <= block->asize);
	block->size = size;
	block->aclass = aclass;

	blocktail_init (block);

	block->cp_idx = cpmgr::scallpointalloc(block, cp);

	// Собрать статистику.
	memory_used += block->size;
	memory_max_used = max(memory_max_used, memory_used);

	return block->ptr + head_zone;
}

void free (void *ptr, callpoint_t cp, uint32_t aclass)
{
	struct block_control *block = getBlockByPtr(ptr);

	if (block == 0) {
		if (ptr != 0) {
			char name[80];
			printf ("\t*** free unknown block %p from %s\n",
				ptr, getCallPonitName(cp, name, 80));
		} else if (free_zero) {
			char name[80];
			printf ("\t*** free zero pointer from %s\n",
				getCallPonitName(cp, name, 80));
		}

		return;
	}

	if ((block->flags & BF_USED) == 0) {
		struct block_control *fblock = begin_block;
		while (fblock < end_block) {
			BOOST_ASSERT (fblock->asize % 16 == 0);

			if (fblock == block) {
				// Блок уже освобожден.
				char name[80];
				printf ("\t*** double free block %p from %s\n",
					ptr, getCallPonitName(cp, name, 80));
				return;
			}

			fblock = nextblock(fblock);
		}
		BOOST_ASSERT (fblock == end_block);

		// Кривой указатель или блок освобожден уже слишком давно.
		char name[80];
		printf ("\t*** invalid pointer for free block %p from %s\n",
			ptr, getCallPonitName(cp, name, 80));
		return;
	}

	if (block->aclass != aclass) {
		BOOST_ASSERT (block->aclass < 3);
		BOOST_ASSERT (aclass < 3);

		const char *allocf[] = {"*alloc", "new", "new[]"};
		const char *freef[] = {"free", "delete", "delete[]"};

		//  Нарушение класса функций
		char aname[80], fname[80];
		printf ("\t*** block allocated over '%s' from %s, free over '%s' from %s\n",
			allocf[block->aclass], getCallPonitName(cpmgr::getCallPoint(block->cp_idx), aname, 80),
			freef[aclass], getCallPonitName(cp, fname, 80));
		BOOST_ASSERT(!"Mismatch function class");
	}

	cpmgr::scallpointfree(block, cp);
	blocktail_check (block);

	BOOST_ASSERT (memory_used >= block->size);
	// статистика.
	memory_used -= block->size;

	block->flags = 0;
	freeblock_init(block);
	cache::storeblock(block);
}

void defrag ()
{
	uint32_t maxfree = 0;

	cache::init();

	struct block_control *block = begin_block;
	while (block < end_block) {
		BOOST_ASSERT (block->asize % 16 == 0);

		if ((block->flags & BF_USED) == 0) {
			freeblock_check(block);

			while (true) {
				struct block_control *nblock = nextblock(block);
				BOOST_ASSERT (nblock <= end_block);
				if (nblock == end_block) break;

				BOOST_ASSERT (nblock->asize % 16 == 0);
				if ((nblock->flags & BF_USED) != 0) break;

				freeblock_check (nblock);
				block->asize += sizeof(struct block_control) + nblock->asize;
			}

			freeblock_init(block);
			cache::storeblock(block);

			maxfree = max(maxfree, block->asize);
		}

		block = nextblock(block);
	}
	BOOST_ASSERT (block == end_block);

	printf ("\t*** defrag. max free block - %u\n", maxfree);
}

uint32_t blocksize (void *ptr)
{
	struct block_control *block = getBlockByPtr(ptr);
	BOOST_ASSERT (block != 0);
	BOOST_ASSERT ((block->flags & BF_USED) != 0);	// Блок должен быть занят, только тогда size актуален.
	return block->size;
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
		__sync_lock_release(&m_lock, UNLOCKED);
	}

	static void init() {
		__sync_lock_release(&m_lock, UNLOCKED);
	}
};

volatile lock_t::lock_state lock_t::m_lock = UNLOCKED;

bool active = false;

void init()
{
	// Для корректного вывода.
	setvbuf(stdout, NULL, _IONBF, 0);

	heapmgr::init();
	cpmgr::init();

	lock_t::init();

	active = true;
}

void finit()
{
	cpmgr::result();
}

static class finit_runner {
public:
	// atexit вызывается раньше, чем деструктор статического класса.
	~finit_runner() { finit(); }
} fr;

void periodic()
{
	// Счетчик выделений. Для отображения статистики памяти.
	static uint32_t scounter = 0;

	scounter++;
	if (scounter % operation_period != 0)
		return;

	// Статистика использования памяти.
	printf ("\t*** Heap used: %u, max: %u\n", memory_used, memory_max_used);

	heapmgr::blocktail_check_all();
	heapmgr::freeblock_check_all();
}

void *alloc (size_t size, callpoint_t cp, uint32_t aclass)
{
	BOOST_ASSERT (size < heap_size);
	if (!active) init();
	lock_t lock;
	periodic();

	void *ptr = heapmgr::alloc(size, cp, aclass);
	if (ptr == 0) {
		// Дефрагментировать и попытаться снова.
		heapmgr::defrag();
		ptr = heapmgr::alloc(size, cp, aclass);

		if (ptr == 0) {
			char name[80];
			printf("\t*** No memory for alloc(%u), called from %s\n",
				uint32_t(size), getCallPonitName(cp, name, 80));
			BOOST_ASSERT(!"No memory");
		}
	}

	BOOST_ASSERT ((unsigned long)ptr % 16 == 0);
	return ptr;
}

void free (void *ptr, callpoint_t cp, uint32_t aclass)
{
	BOOST_ASSERT(active);
	lock_t lock;
	periodic();
	heapmgr::free(ptr, cp, aclass);
}

uint32_t blocksize(void *ptr)
{
	BOOST_ASSERT(active);
	lock_t lock;

	return heapmgr::blocksize(ptr);
}

bool AvailCallPoint(callpoint_t cp)
{
	if (!active) init();
	lock_t lock;

	// Делаем это только после инициализации. для этого и враппер
	return cpmgr::AvailCallPoint(cp);
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

	while (!heapif::AvailCallPoint(reinterpret_cast<callpoint_t>(ip))) {
		if (unw_step(&cursor) == 0) break;
		unw_get_reg(&cursor, UNW_REG_IP, &ip);
	}

	return reinterpret_cast<callpoint_t>(ip);
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
