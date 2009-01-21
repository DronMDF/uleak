//
// Copyright (c) 2000-2008 Андрей Валяев (dron@infosec.ru)
// This code is licenced under the GPL3 (http://www.gnu.org/licenses/#GPL)
//

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>

#include <pthread.h>

#include <algorithm>
using namespace std;

namespace {

// Частота вызова переодических операций.
// Меряется количествами вызовов функций alloc/free
const uint32_t operation_period = 3000;

// Ругаться на free(0)
const bool free_zero = false;

// Заполнение освобождаемых блоков и контроль использования после освобождения (может производиться с большо-о-ой задержкой)
const bool check_free = true;
const bool check_free_repetition = true;

// Контролировать пространство за пределами блока
const bool check_tail = true;
const bool check_tail_repetition = true;
// Размер буферной зоны
const uint32_t tail_zone = check_tail ? 32 : 0;

// Фильтровать стандартные функции из CallPoint's
const bool function_filter = true;

// 16 мегабайт - размер хипа. его должно хватать.
const uint32_t heap_size = 32 * 1024 * 1024;

// количество точек вызова. Их должно хватать. если не хватает будет assert.
const uint32_t call_points = 4096;

// Допустимое количество блоков на точку. во избежание лишней ругани.
const uint32_t block_limit = 1000;

// Отображать стек вызова. В случае лика.
const bool show_leak_callstack = false;

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
	uint32_t cp;
	uint32_t size;
	uint32_t oldcp;
	uint32_t aclass;	// класс операций памяти
	uint32_t reserved[3];	// Можно было бы упихнуть в 16, ну да пофиг.
};

struct callpoint {
	uint32_t cp;
	uint32_t current_blocks;
	uint32_t max_blocks;
	uint32_t size;
};

bool isActive = false;
bool isLockable = false;

pthread_mutex_t smutex = PTHREAD_MUTEX_INITIALIZER;

uint8_t sheap[heap_size];
struct callpoint scps[call_points];

// -----------------------------------------------------------------------------
// Утилиты всякие

bool isFunction (void *func, uint32_t cp, size_t fsz)
{
	if ((uint32_t)func < cp && cp - (uint32_t)func < fsz)
		return true;

	return false;
}

// -----------------------------------------------------------------------------
// Фильтрация стандартный функций из стека вызова.
// Было бы удобнее, если бы я мог получить имя функции по адресу.
// Я не знаю как это сделать.

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

// Это такие хитрые ссылки на функции...
// extern "C" void *_ZNSs4_Rep9_S_createEjjRKSaIcE;
// extern "C" void *_ZNSbIwSt11char_traitsIwESaIwEE4_Rep9_S_createEjjRKS1_;
// extern "C" void *_ZN9__gnu_cxx13new_allocatorI6OpenedE8allocateEjPKv;
// extern "C" void *_ZN9__gnu_cxx13new_allocatorIN10__gnu_norm10_List_nodeISt4pairISs14TDateTimeEntryEEEE8allocateEjPKv;
// extern "C" void *_ZN9__gnu_cxx13new_allocatorIN14TDateTimeEntry12TimeIntervalEE8allocateEjPKv;
// extern "C" void *_ZN9__gnu_cxx13new_allocatorIN10__gnu_norm10_List_nodeIN5boost13intrusive_ptrINS3_10statechart6detail10leaf_stateISaIvENS6_11rtti_policyEEEEEEEE8allocateEjPKv;
// extern "C" void *_ZN9__gnu_cxx13new_allocatorI8PppStateE8allocateEjPKv;
// extern "C" void *_ZNSs12_S_constructIPKcEEPcT_S3_RKSaIcESt20forward_iterator_tag;
// extern "C" void *_ZN13shared_membufC1Ej;
// extern "C" void *_ZN9__gnu_cxx13new_allocatorIN5boost11multi_index6detail18ordered_index_nodeINS4_INS3_15index_node_baseIN13ClientManager11TimeoutInfoEEEEEEEE8allocateEjPKv;
// extern "C" void *_ZN10__gnu_norm10_List_baseISt4pairISs14TDateTimeEntryESaIS3_EE11_M_get_nodeEv;
// extern "C" void *_ZN10__gnu_norm12_Vector_baseIN14TDateTimeEntry12TimeIntervalESaIS2_EE11_M_allocateEj;
// extern "C" void *_ZNSs7reserveEj;
// extern "C" void *_ZN5boost10statechart6detail8allocateI6OpenedSaIvEEEPvj;
// extern "C" void *_ZNSsC1EPKcRKSaIcE;
// extern "C" void *_ZN10__gnu_norm12_Vector_baseIN14TDateTimeEntry12TimeIntervalESaIS2_EEC2EjRKS3_;
// extern "C" void *_ZN10__gnu_norm4listISt4pairISs14TDateTimeEntryESaIS3_EE14_M_create_nodeERKS3_;
// extern "C" void *_ZN5boost10statechart12simple_stateI6Opened8PppStateNS_3mpl4listIN4mpl_2naES7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_EELNS0_12history_modeE0EEnwEj;
// extern "C" void *_ZN5boost10statechart6detail8allocateI8PppStateSaIvEEEPvj;
// extern "C" void *_ZN9__gnu_cxx13new_allocatorIN10__gnu_norm10_List_nodeIN5boost13intrusive_ptrINS3_10statechart6detail10leaf_stateISaIvENS6_11rtti_policyEEEEEEEE8allocateEjPKv;
// extern "C" void *_ZN9__gnu_cxx13new_allocatorIN10__gnu_norm10_List_nodeI7TSubnetEEE8allocateEjPKv;
// extern "C" void *_ZNSs6appendEPKcj;
// extern "C" void *_ZN5boost6detail12shared_countC1I10iALG_R3411EEPT_;
// extern "C" void *_ZN5boost6detail12shared_countC1IPcNS_21checked_array_deleterIcEEEET_T0_;
// extern "C" void *_ZN10__gnu_norm4listISt4pairISs14TDateTimeEntryESaIS3_EE9_M_insertENS_14_List_iteratorIS3_EERKS3_;
// extern "C" void *_ZN10__gnu_norm6vectorIN14TDateTimeEntry12TimeIntervalESaIS2_EEC2ERKS4_;
// extern "C" void *_ZN10__gnu_norm10_List_baseIN5boost13intrusive_ptrINS1_10statechart6detail10leaf_stateISaIvENS4_11rtti_policyEEEEESaIS9_EE11_M_get_nodeEv;
// extern "C" void *_ZN5boost10statechart12simple_stateI8PppState12StateMachine7InitialLNS0_12history_modeE0EEnwEj;
// extern "C" void *_ZN5boost12shared_arrayIcEC1EPc;
// extern "C" void *_ZN5boost10shared_ptrI10iALG_R3411EC1IS1_EEPT_;
// extern "C" void *_ZN9__gnu_cxx13new_allocatorISt13_Rb_tree_nodeISt4pairIKSsN13ClientManager8PeerInfoEEEE8allocateEjPKv;
// extern "C" void *_ZN10__gnu_norm4listISt4pairISs14TDateTimeEntryESaIS3_EE18_M_insert_dispatchINS_20_List_const_iteratorIS3_EEEEvNS_14_List_iteratorIS3_EET_SB_12__false_type;
// extern "C" void *_ZN14TDateTimeEntryC1ERKS_;
// extern "C" void *_ZN5boost10statechart12simple_stateI8PppState12StateMachine7InitialLNS0_12history_modeE0EE17shallow_constructERKPNS0_13state_machineIS3_S2_SaIvENS0_25null_exception_translatorEEERSA_;
// extern "C" void *_ZN10__gnu_norm4listIN5boost13intrusive_ptrINS1_10statechart6detail10leaf_stateISaIvENS4_11rtti_policyEEEEESaIS9_EE14_M_create_nodeERKS9_;
// extern "C" void *_ZN5boost10statechart12simple_stateI6Opened8PppStateNS_3mpl4listIN4mpl_2naES7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_EELNS0_12history_modeE0EE17shallow_constructERKNS_13intrusive_ptrIS3_EERNS0_13state_machineI12StateMachineS3_SaIvENS0_25null_exception_translatorEEE;
// extern "C" void *_ZN5boost11multi_index21multi_index_containerIN13ClientManager11TimeoutInfoENS0_10indexed_byINS0_18ordered_non_uniqueINS0_6memberIS3_7timevalXadL_ZNS3_2tvEEEEEN4mpl_2naESA_EENS0_14ordered_uniqueINS6_IS3_SsXadL_ZNS3_4hookEEEEESA_SA_EESA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_EESaIS3_EE13allocate_nodeEv;
// extern "C" void *_ZN9__gnu_cxx13new_allocatorI7ClosingE8allocateEjPKv;

uint32_t getFilteredCallPoint(uint32_t ocp)
{
// 	if (	isFunction(&_ZNSs4_Rep9_S_createEjjRKSaIcE, ocp, 0x100) ||
// 		isFunction(&_ZNSbIwSt11char_traitsIwESaIwEE4_Rep9_S_createEjjRKS1_, ocp, 0x100) ||
// 		isFunction(&_ZN9__gnu_cxx13new_allocatorI6OpenedE8allocateEjPKv, ocp, 0x20) ||
// 		isFunction(&_ZN9__gnu_cxx13new_allocatorIN10__gnu_norm10_List_nodeISt4pairISs14TDateTimeEntryEEEE8allocateEjPKv, ocp, 0x40) ||
// 		isFunction(&_ZN9__gnu_cxx13new_allocatorIN14TDateTimeEntry12TimeIntervalEE8allocateEjPKv, ocp, 0x20) ||
// 		isFunction(&_ZN9__gnu_cxx13new_allocatorIN10__gnu_norm10_List_nodeIN5boost13intrusive_ptrINS3_10statechart6detail10leaf_stateISaIvENS6_11rtti_policyEEEEEEEE8allocateEjPKv, ocp, 0x10) ||
// 		isFunction(&_ZN9__gnu_cxx13new_allocatorIN5boost11multi_index6detail18ordered_index_nodeINS4_INS3_15index_node_baseIN13ClientManager11TimeoutInfoEEEEEEEE8allocateEjPKv, ocp, 0x20) ||
// 		isFunction(&_ZN9__gnu_cxx13new_allocatorI8PppStateE8allocateEjPKv, ocp, 0x20) ||
// 		isFunction(&_ZNSs12_S_constructIPKcEEPcT_S3_RKSaIcESt20forward_iterator_tag, ocp, 0x80) ||
// 		isFunction(&_ZN13shared_membufC1Ej, ocp, 0x40) ||
// 		isFunction(&_ZN10__gnu_norm10_List_baseISt4pairISs14TDateTimeEntryESaIS3_EE11_M_get_nodeEv, ocp, 0x40) ||
// 		isFunction(&_ZN10__gnu_norm12_Vector_baseIN14TDateTimeEntry12TimeIntervalESaIS2_EE11_M_allocateEj, ocp, 0x40) ||
// 		isFunction(&_ZNSs7reserveEj, ocp, 0x100) ||
// 		isFunction(&_ZN5boost10statechart6detail8allocateI6OpenedSaIvEEEPvj, ocp, 0x100) ||
// 		isFunction(&_ZNSsC1EPKcRKSaIcE, ocp, 0x40) ||
// 		isFunction(&_ZN10__gnu_norm12_Vector_baseIN14TDateTimeEntry12TimeIntervalESaIS2_EEC2EjRKS3_, ocp, 0x80) ||
// 		isFunction(&_ZN10__gnu_norm4listISt4pairISs14TDateTimeEntryESaIS3_EE14_M_create_nodeERKS3_, ocp, 0x80) ||
// 		isFunction(&_ZN5boost10statechart12simple_stateI6Opened8PppStateNS_3mpl4listIN4mpl_2naES7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_EELNS0_12history_modeE0EEnwEj, ocp, 0x20) ||
// 		isFunction(&_ZN5boost10statechart6detail8allocateI8PppStateSaIvEEEPvj, ocp, 0x100) ||
// 		isFunction(&_ZN9__gnu_cxx13new_allocatorIN10__gnu_norm10_List_nodeIN5boost13intrusive_ptrINS3_10statechart6detail10leaf_stateISaIvENS6_11rtti_policyEEEEEEEE8allocateEjPKv, ocp, 0x20) ||
// 		isFunction(&_ZN9__gnu_cxx13new_allocatorIN10__gnu_norm10_List_nodeI7TSubnetEEE8allocateEjPKv, ocp, 0x20) ||
// 		isFunction(&_ZNSs6appendEPKcj, ocp, 0x100) ||
// 		isFunction(&_ZN5boost6detail12shared_countC1I10iALG_R3411EEPT_, ocp, 0x100) ||
// 		isFunction(&_ZN5boost6detail12shared_countC1IPcNS_21checked_array_deleterIcEEEET_T0_, ocp, 0x100) ||
// 		isFunction(&_ZN10__gnu_norm4listISt4pairISs14TDateTimeEntryESaIS3_EE9_M_insertENS_14_List_iteratorIS3_EERKS3_, ocp, 0x40) ||
// 		isFunction(&_ZN10__gnu_norm6vectorIN14TDateTimeEntry12TimeIntervalESaIS2_EEC2ERKS4_, ocp, 0x100) ||
// 		isFunction(&_ZN10__gnu_norm10_List_baseIN5boost13intrusive_ptrINS1_10statechart6detail10leaf_stateISaIvENS4_11rtti_policyEEEEESaIS9_EE11_M_get_nodeEv, ocp, 0x40) ||
// 		isFunction(&_ZN5boost10statechart12simple_stateI8PppState12StateMachine7InitialLNS0_12history_modeE0EEnwEj, ocp, 0x20) ||
// 		isFunction(&_ZN5boost12shared_arrayIcEC1EPc, ocp, 0x40) ||
// 		isFunction(&_ZN5boost10shared_ptrI10iALG_R3411EC1IS1_EEPT_, ocp, 0x80) ||
// 		isFunction(&_ZN9__gnu_cxx13new_allocatorISt13_Rb_tree_nodeISt4pairIKSsN13ClientManager8PeerInfoEEEE8allocateEjPKv, ocp, 0x20) ||
// 		isFunction(&_ZN10__gnu_norm4listISt4pairISs14TDateTimeEntryESaIS3_EE18_M_insert_dispatchINS_20_List_const_iteratorIS3_EEEEvNS_14_List_iteratorIS3_EET_SB_12__false_type, ocp, 0x80) ||
// 		isFunction(&_ZN14TDateTimeEntryC1ERKS_, ocp, 0x40) ||
// 		isFunction(&_ZN5boost10statechart12simple_stateI8PppState12StateMachine7InitialLNS0_12history_modeE0EE17shallow_constructERKPNS0_13state_machineIS3_S2_SaIvENS0_25null_exception_translatorEEERSA_, ocp, 0x100) ||
// 		isFunction(&_ZN10__gnu_norm4listIN5boost13intrusive_ptrINS1_10statechart6detail10leaf_stateISaIvENS4_11rtti_policyEEEEESaIS9_EE14_M_create_nodeERKS9_, ocp, 0x80) ||
// 		isFunction(&_ZN5boost10statechart12simple_stateI6Opened8PppStateNS_3mpl4listIN4mpl_2naES7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_EELNS0_12history_modeE0EE17shallow_constructERKNS_13intrusive_ptrIS3_EERNS0_13state_machineI12StateMachineS3_SaIvENS0_25null_exception_translatorEEE, ocp, 0x100) ||
// 		isFunction(&_ZN5boost11multi_index21multi_index_containerIN13ClientManager11TimeoutInfoENS0_10indexed_byINS0_18ordered_non_uniqueINS0_6memberIS3_7timevalXadL_ZNS3_2tvEEEEEN4mpl_2naESA_EENS0_14ordered_uniqueINS6_IS3_SsXadL_ZNS3_4hookEEEEESA_SA_EESA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_SA_EESaIS3_EE13allocate_nodeEv, ocp, 0x40) ||
// 		isFunction(&_ZN9__gnu_cxx13new_allocatorI7ClosingE8allocateEjPKv, ocp, 0x20) //||
// 
// 	)
// 	{
// 		int i = 0;
// 		while (reinterpret_cast<uint32_t>(getReturnAddress(i)) != ocp) i++;
// 		return getFilteredCallPoint (reinterpret_cast<uint32_t>(getReturnAddress(i + 1)));
// 	}

	return ocp;
}

// -----------------------------------------------------------------------------
// менеджер точек вызова

bool scallpointalloc(const struct block_control *block)
{
	for (uint32_t i = 0; i < call_points; i++) {
		if (scps[i].cp == block->cp || scps[i].cp == 0) {
			scps[i].current_blocks++;
			scps[i].cp = block->cp;

			if (scps[i].current_blocks > scps[i].max_blocks)
			{
				scps[i].max_blocks = scps[i].current_blocks;

				printf ("\t*** leak %u from 0x%08x with %ssize %u\n",
					scps[i].max_blocks, block->cp,
					scps[i].size == block->size ? "" : "variable ", block->size);

				if (show_leak_callstack) {
					printf ("\t\t%p -> %p -> %p -> %p -> %p\n",
						__builtin_return_address(7),
						__builtin_return_address(6),
						__builtin_return_address(5),
						__builtin_return_address(4),
						__builtin_return_address(3));
				}

			}

			scps[i].size = block->size;

			return true;
		}
	}

	return false;
}

bool scallpointfree(const struct block_control *block, uint32_t cp)
{
	assert(block->cp != 0);

	for (uint32_t i = 0; i < call_points && scps[i].cp != 0; i++) {
		if (scps[i].cp == block->cp) {
			if (scps[i].current_blocks == 0) {
				printf ("\t*** mextra free for block size %u allocated from 0x%08x, free from 0x%08x\n",
					block->size, block->cp, cp);

			} else {
				scps[i].current_blocks--;
			}

			return true;
		}
	}

	return false;
}

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
		printf ("\t*** corrupted block tail, %u bytes, allocated from 0x%08x, size %u\n",
			corrupted, block->cp, block->size);
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
		printf ("\t*** modifyed free block %p, allocated from 0x%08x with size %u\n",
			bptr + sizeof(struct block_control), block->oldcp, block->size);
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

	for (uint32_t i = 0; i < call_points; i++) {
		scps[i].cp = 0;
		scps[i].size = 0;
		scps[i].current_blocks = 0;
		scps[i].max_blocks = block_limit;
	}

	// Для корректного вывода.
	setvbuf(stdout, NULL, _IONBF, 0);

	isActive = true;

	pthread_mutex_init(&smutex, NULL);

	isLockable = true;
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

// Блокировки идут на этом уровне.

void *sonealloc (size_t size, uint32_t cp, uint32_t aclass)
{
	if (!isActive) sinit();

	speriodic();

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

			if (function_filter) {
				block->oldcp = block->cp = getFilteredCallPoint(cp);
			} else {
				block->oldcp = block->cp = cp;
			}

			assert (size <= block->asize);
			block->size = size;

			block->aclass = aclass;

			if (check_tail) {
				sblock_tail_init (block, bptr);
			}

			// Зарегистрировать точку вызова среди call_points
			assert (scallpointalloc (block));

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

void sfree (void *ptr, uint32_t cp, uint32_t aclass)
{
	assert (isActive);

	slock lock;

	speriodic();

	if (ptr < sheap || ptr >= sheap + heap_size) {
		if (ptr != 0 || free_zero) {
			printf ("\t*** free unknown block %p from 0x%08x\n", ptr, cp);
		}

		return;
	}

	uint8_t *bptr = reinterpret_cast<uint8_t *>(ptr) - sizeof (struct block_control);
	struct block_control *block = reinterpret_cast<struct block_control *>(bptr);

	if (block->cp == 0 || block->cp == FFILL32) {
		// Блок уже освобожден.
		printf ("\t*** double free block %p from 0x%08x\n", ptr, cp);
		return;
	}

	if (block->aclass != aclass) {
		assert (block->aclass < 3);
		assert (aclass < 3);

		const char *allocf[] = {"*alloc", "new", "new[]"};
		const char *freef[] = {"free", "delete", "delete[]"};

		//  Нарушение класса функций
		printf ("\t*** block allocated over '%s' from 0x%08x, "
			"free over '%s' from 0x%08x\n",
			allocf[block->aclass], block->cp,
			freef[aclass], cp);

		assert(block->aclass != aclass);
		return;
	}

	if (!scallpointfree (block, cp)) {
		printf ("\t*** free nonalloc block %p from 0x%08x\n", ptr, cp);
		return;
	}

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

uint32_t sblocksize(void *ptr)
{
	assert (isActive);
	uint8_t *bptr = reinterpret_cast<uint8_t *>(ptr) - sizeof(struct block_control);
	struct block_control *block = reinterpret_cast<struct block_control *>(bptr);
	assert (block->cp != 0);
	return block->size;
}

// Это парочка вспомогательных неблокируемых функций.

void *salloc (size_t size, uint32_t cp, uint32_t aclass)
{
	assert (size < heap_size);

	void *ptr = sonealloc (size, cp, aclass);

	if (ptr == 0) {
		// Дефрагментировать и попытаться снова.
		sdefrag ();
		ptr = sonealloc (size, cp, aclass);

		if (ptr == 0) {
			printf ("\t*** No memory for alloc(%u), called from 0x%08x\n", size, cp);
		}

		assert (ptr != 0);
	}

	assert ((uint32_t)ptr % 16 == 0);
	return ptr;
}

// Реаллоку необходимо знать прежний размер блока,
// а это можно узнать только в менеджере.
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

uint32_t getCallPoint(const void *stack)
{
	const uint32_t *sptr = reinterpret_cast<const uint32_t *>(stack);
	return sptr[-1];
}

} // static namespace

// -----------------------------------------------------------------------------
// Заместители стандартных функций должны отслеживать точки из которых их вызывают

// libc
extern "C"
void *malloc (size_t size)
{
	const uint32_t cp = getCallPoint(&size);
	return salloc (size, cp, CLASS_C);
}

extern "C"
void *calloc (size_t number, size_t size)
{
	const uint32_t cp = getCallPoint(&number);
	void *ptr = salloc (number * size, cp, CLASS_C);
	// calloc возвращает чищенную память!
	memset (ptr, 0, number * size);
	return ptr;
}

extern "C"
void *realloc (void *ptr, size_t size)
{
	const uint32_t cp = getCallPoint(&ptr);
	return srealloc(ptr, size, cp, CLASS_C);
}

extern "C"
void *reallocf (void *ptr, size_t size)
{
	const uint32_t cp = getCallPoint(&ptr);

	void *nptr = srealloc(ptr, size, cp, CLASS_C);
	if (nptr == 0 && ptr != 0)
		sfree (ptr, cp, CLASS_C);

	return nptr;
}

extern "C"
void free (void *ptr)
{
	const uint32_t cp = getCallPoint(&ptr);
	sfree (ptr, cp, CLASS_C);
}

extern "C"
char *strdup(const char *str)
{
	const uint32_t cp = getCallPoint(&str);

	char *str2 = reinterpret_cast<char *>(salloc(strlen(str) + 1, cp, CLASS_C));
	strcpy (str2, str);
	return str2;
}

// с++ runtime.
void *operator new(size_t size)
{
	const uint32_t cp = getCallPoint(&size);
	return salloc (size, cp, CLASS_NEW);
}

void operator delete (void *ptr) throw()
{
	const uint32_t cp = getCallPoint(&ptr);
	sfree (ptr, cp, CLASS_NEW);
}

void *operator new[] (unsigned int size)
{
	const uint32_t cp = getCallPoint(&size);
	return salloc (size, cp, CLASS_NEW_ARRAY);
}

void operator delete[] (void *ptr) throw()
{
	const uint32_t cp = getCallPoint(&ptr);
	sfree (ptr, cp, CLASS_NEW_ARRAY);
}
