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

// Создрал из википедии. интересно под какой лицензией исходники публикуются там?

/*
  Name  : CRC-16 CCITT
  Poly  : 0x11021       x^16 + x^12 + x^5 + 1
  Init  : 0xFFFF
  Revert: false
  XorOut: 0x0000
  Check : 0x29B1 ("123456789")
  MaxLen: 4095 байт (32767 бит) - обнаружение
    одинарных, двойных, тройных и всех нечетных ошибок
*/
uint16_t crc16(const uint8_t *ptr, size_t len)
{
	static const uint16_t Crc16Table[256] = {
		0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
		0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
		0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
		0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
		0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
		0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
		0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
		0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
		0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
		0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
		0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
		0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
		0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
		0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
		0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
		0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
		0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
		0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
		0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
		0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
		0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
		0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
		0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
		0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
		0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
		0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
		0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
		0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
		0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
		0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
		0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
		0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
	};

	uint16_t crc = 0xFFFF;
	while (len--) {
		crc = (crc << 8) ^ Crc16Table[(crc >> 8) ^ *ptr++];
	}
 	return crc;
}
} // anonymous namespace

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
const uint32_t tail_zone = check_tail ? 16 : 0;

// голова блока, пока просто выделим не проверяя содержимого.
const uint32_t head_zone = check_tail ? 16 : 0;

// размер хипа.
const uint32_t heap_size = 256 * 1024 * 1024;

// количество точек вызова. Их должно хватать. если не хватает будет BOOST_ASSERT.
const int call_points = 8192;

// Допустимое количество блоков на точку. во избежание лишней ругани.
const uint32_t block_limit = 20000;

// Поиск мемориликов по таймаутам.
const bool block_timeout = true;
const time_t block_timeout_value = 5 * 60;	// пока поставим 5 минут.

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
		struct {
			uint32_t size;
			// crc_16 чтобы упихнуть весь заголовок в 16 байт.
			uint16_t crc;
			// Можно хранить младшие 16 бит time_t,
			// переполнение будет происходить раз в ~18 часов.
			// Но оно нам не страшно особо.
			uint16_t timeout;
		};

		struct block_control *next;
	};

	uint8_t ptr[0];
} __attribute__((packed));

enum {
	BF_USED = 0x01,
	BF_FFILL = 0x02,
	BF_TIMEOUT = 0x04,	// В течении определенного времени не менялся.
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

	// голова
	memset (block->ptr, AFILL, head_zone);
	// хвост
	memset (block->ptr + head_zone + block->size, AFILL, block->asize - (head_zone + block->size));
}

void blocktail_check (const struct block_control *block)
{
	BOOST_ASSERT ((block->flags & BF_USED) != 0);

	if (!check_tail) return;

	const size_t tail_offset = block->size + head_zone;

	for (int i = head_zone - 1; i >= 0; i--) {
		if (block->ptr[i] != AFILL) {
			char name[80];
			printf ("\t*** corrupted block head, %u bytes, allocated from %s, size %u\n",
				i, getCallPonitName(cpmgr::getCallPoint(block->cp_idx), name, 80), block->size);
			BOOST_ASSERT(!"Corrupted block head");
		}
	}

	for (int i = block->asize - tail_offset - 1; i >= 0; i--) {
		if (block->ptr[tail_offset + i] != AFILL) {
			char name[80];
			printf ("\t*** corrupted block tail, %u bytes, allocated from %s, size %u\n",
				i, getCallPonitName(cpmgr::getCallPoint(block->cp_idx), name, 80), block->size);
			BOOST_ASSERT(!"Corrupted block tail");
		}
	}
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

// -----------------------------------------------------------------------------
// Таймауты блоков.

void blocktimeout_init(struct block_control *block)
{
	if (!block_timeout) return;

	block->crc = crc16(block->ptr + head_zone, block->size);
	block->timeout = uint16_t(time(0) & 0xffff);
}

void blocktimeout_check(struct block_control *block)
{
	if (!block_timeout) return;

	uint16_t crc = crc16(block->ptr + head_zone, block->size);

	if (block->crc != crc) {
		block->crc = crc;
		block->timeout = uint16_t(time(0) & 0xffff);
		return;
	}

	if ((block->flags & BF_TIMEOUT) == 0) {
		// Из за короткой формы таймаута приходится немного извращаться.
		time_t to = (time(0) - block->timeout) & 0xffff;
		if (to < block_timeout_value)
			return;

		char name[80];
		printf ("\t*** timeout leak block %p, allocated from %s with %ssize %u\n",
			block->ptr + head_zone, getCallPonitName(cpmgr::cparray[block->cp_idx].cp, name, 80),
			(cpmgr::cparray[block->cp_idx].size == block->size) ? "" : "variable ", block->size);

		block->flags |= BF_TIMEOUT;
	}
}

// -----------------------------------------------------------------------------
// Проверка всех блоков хипа.

void block_check_all ()
{
	if (!check_free_repetition && !check_tail_repetition) return;

	struct block_control *block = begin_block;
	while (block < end_block) {
		BOOST_ASSERT (block->asize % 16 == 0);

		if ((block->flags & BF_USED) == 0) {
			freeblock_check(block);
		} else {
			blocktail_check(block);
			blocktimeout_check(block);
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
	blocktimeout_init(block);

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

	if ((block->flags & BF_TIMEOUT) != 0) {
		char name[80];
		printf ("\t*** sorry, block %p, %u bytes, allocated from %s is not timeouted!\n",
			block->ptr + head_zone, block->size,
			getCallPonitName(cpmgr::cparray[block->cp_idx].cp, name, 80));
	}

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

	heapmgr::block_check_all();
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
	// Этот код может упасть, чтобы этого избежать надо увеличивать block_limit
	callpoint_t cp = __builtin_return_address(1);
	if (heapif::AvailCallPoint(cp)) return cp;
	cp = __builtin_return_address(2);
	if (heapif::AvailCallPoint(cp)) return cp;
	cp = __builtin_return_address(3);
	if (heapif::AvailCallPoint(cp)) return cp;
	cp = __builtin_return_address(4);
	if (heapif::AvailCallPoint(cp)) return cp;
	cp = __builtin_return_address(5);
	if (heapif::AvailCallPoint(cp)) return cp;
	cp = __builtin_return_address(6);
	if (heapif::AvailCallPoint(cp)) return cp;
	cp = __builtin_return_address(7);
	if (heapif::AvailCallPoint(cp)) return cp;
	cp = __builtin_return_address(8);
	if (heapif::AvailCallPoint(cp)) return cp;
	cp = __builtin_return_address(9);
	if (heapif::AvailCallPoint(cp)) return cp;
	cp = __builtin_return_address(10);
	return cp;
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
