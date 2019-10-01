/* radare - LGPL - Copyright 2019 - pancake */

#include <r_anal.h>

#define NEWBBAPI 1

#if NEWBBAPI
#define BBAPI_PRELUDE(x)
#else
#define BBAPI_PRELUDE(x) return x
#endif

R_API RAnalBlock *r_anal_block_new (ut64 addr, int size) {
	RAnalBlock *b = r_anal_bb_new ();
	if (b) {
		b->addr = addr;
		b->size = size;
	}
	return b;
}

R_API void r_anal_block_free(RAnalBlock *bb) {
	r_anal_bb_free (bb);
}

R_API void r_anal_add_function(RAnal *anal, RAnalFunction *fcn) {
	r_list_append (anal->fcns, fcn);
}

static ut64 __bbHashKey(ut64 addr) {
	return addr >> 4;
}

R_API RAnalBlock *r_anal_get_block(RAnal *anal, ut64 addr) {
	BBAPI_PRELUDE (NULL);
	const ut64 k = __bbHashKey (addr);
	RList *list = ht_up_find (anal->ht_bbs, k, NULL);
	if (list) {
		RAnalBlock *b;
		RListIter *iter;
		r_list_foreach (list, iter, b) {
			if (R_BETWEEN (b->addr, addr, b->addr + b->size)) {
				return b;
			}
		}
	}
	return NULL;
}

R_API void r_anal_block_ref (RAnal *anal, RAnalBlock *bb) {
	bb->ref++;
}

R_API bool r_anal_add_block(RAnal *anal, RAnalBlock *bb) {
	BBAPI_PRELUDE (NULL);
	r_return_val_if_fail (anal && bb, false);
	const ut64 k = __bbHashKey (bb->addr);
	RAnalBlock *b = r_anal_get_block (anal, bb->addr);
	if (b) {
		return false;
	}
	RList *list = ht_up_find (anal->ht_bbs, k, NULL);
	if (!list) {
		list = r_list_new ();
		ht_up_insert (anal->ht_bbs, k, list);
	}
	r_anal_block_ref (anal, bb);
	r_list_append (list, bb);
	return true;
}

R_API const RList *r_anal_get_functions(RAnal *anal, ut64 addr) {
	RAnalBlock *bb = r_anal_get_block (anal, addr);
	return bb? bb->fcns: NULL;
}

R_API void r_anal_del_block(RAnal *anal, RAnalBlock *bb) {
	BBAPI_PRELUDE (NULL);
	const ut64 k = __bbHashKey (bb->addr);
	RList *list = ht_up_find (anal->ht_bbs, k, NULL);
	if (list) {
		RAnalBlock *b;
		RAnalFunction *f;
		RListIter *iter, *iter2;
		r_list_foreach (list, iter, b) {
			if (R_BETWEEN (b->addr, bb->addr, b->addr + b->size)) {
				r_list_foreach (b->fcns, iter2, f) {
					r_list_delete_data (f->bbs, b);
				}
				r_list_delete (list, iter);
				break;
			}
		}
	}
	// bbs.del(bb);
}

R_API RAnalFunction *r_anal_function_new(ut64 addr, const char *name) {
	RAnalFunction *fcn = r_anal_fcn_new ();
	free (fcn->name);
	if (name) {
		fcn->name = strdup (name);
	}
	return fcn;
}

R_API void r_anal_function_add_block(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb) {
	(void)r_anal_add_block (anal, bb); // register basic block globally
	r_list_append (bb->fcns, fcn); // associate the given fcn with this bb
	r_list_append (fcn->bbs, bb); // TODO: avoid double insert the same bb
#if USE_SDB_CACHE
	sdb_ptr_set (HB, sdb_fmt (SDB_KEY_BB, fcn->addr, bb->addr), bb, NULL);
#endif
	if (anal->cb.on_fcn_bb_new) {
		anal->cb.on_fcn_bb_new (anal, anal->user, fcn, bb);
	}
}

R_API void r_anal_function_del_block(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb) {
	r_list_delete_data (bb->fcns, fcn);
	r_list_delete_data (fcn->bbs, bb);
	(void)r_anal_del_block (anal, bb); // TODO: honor unref
}

R_API void r_anal_block_unref (RAnal *anal, RAnalBlock *bb) {
	bb->ref--;
	if (bb->ref < 1) {
		r_anal_del_block (anal, bb);
		r_anal_block_free (bb);
	}
}

R_API void r_anal_function_free(RAnal *anal, RAnalFunction *f) {
	RListIter *iter;
	RAnalBlock *b;
	r_list_foreach (f->bbs, iter, b) {
		r_anal_block_unref (anal, b);
		iter->data = NULL;
	}
	r_anal_fcn_free (f);
}

R_API void r_anal_del_function(RAnal *anal, RAnalFunction *fcn) {
	r_anal_function_free (anal, fcn);
	r_list_free (fcn->bbs);
#if 0
	RAnalBlock *bb;
	RListIter *iter;
	fcn.bbs.free();
	fcns.del(fcn);
	fcn.free();
#endif
}
