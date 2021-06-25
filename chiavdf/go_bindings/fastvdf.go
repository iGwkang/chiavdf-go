package go_bindings

/********************************************************
 * Description : chiavdf go wrapper
 * Author      : Gwkang
 * Email       : 975500206@qq.com
 * Version     : 1.0
 * History     :
 * Copyright(C): 2021
 ********************************************************/

/*
#cgo CFLAGS: -I..
#cgo CXXFLAGS: -I.. -std=c++14
#cgo !windows LDFLAGS: -L${SRCDIR} -lstdc++ -lchiavdf -lgmp
//#cgo windows LDFLAGS: -L${SRCDIR} -L${SRCDIR}/Release -LC:/msys64/usr/lib -lstdc++ -lchiavdf -lgmp
#include <stdlib.h>
#include "fastvdf.h"
*/
import "C"
import (
	"unsafe"
)

const BQFC_FORM_SIZE = 100

func CreateDiscriminant(challenge_hash []byte, discriminant_size_bits uint64) string {
	cb := C.struct_ConstBytes{
		data: (*C.uchar)(unsafe.Pointer(&challenge_hash[0])),
		len:  C.int(len(challenge_hash)),
	}
	cs := C.CreateDiscriminantWrapper(cb, C.uint64_t(discriminant_size_bits))
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs)
}

func VerifyWesolowski(discriminant string, x_s, y_s, proof_s []byte, num_iterations uint64) bool {
	var xs, ys, proofs C.struct_ConstBytes

	xs.data = (*C.uchar)(unsafe.Pointer(&x_s[0]))
	xs.len = C.int(len(x_s))

	ys.data = (*C.uchar)(unsafe.Pointer(&y_s[0]))
	ys.len = C.int(len(y_s))

	proofs.data = (*C.uchar)(unsafe.Pointer(&proof_s[0]))
	proofs.len = C.int(len(proof_s))

	return bool(C.VerifyWesolowskiWrapper((*C.char)(unsafe.Pointer(&([]byte(discriminant)[0]))), xs, ys, proofs, C.uint64_t(num_iterations)))
}

func VerifyNWesolowski(discriminant string, x_s, proof_s []byte, num_iterations, disc_size_bits, recursion uint64) bool {
	var xs, proofs C.struct_ConstBytes
	xs.data = (*C.uchar)(unsafe.Pointer(&x_s[0]))
	xs.len = C.int(len(x_s))

	proofs.data = (*C.uchar)(unsafe.Pointer(&proof_s[0]))
	proofs.len = C.int(len(proof_s))

	return bool(C.VerifyNWesolowskiWrapper((*C.char)(unsafe.Pointer(&([]byte(discriminant)[0]))), xs, proofs, C.uint64_t(num_iterations), C.uint64_t(disc_size_bits), C.uint64_t(recursion)))
}

func Prove(challenge_hash, x_s []byte, discriminant_size_bits, num_iterations uint64) []byte {
	hash := C.struct_ConstBytes{
		data: (*C.uchar)(unsafe.Pointer(&challenge_hash[0])),
		len:  C.int(len(challenge_hash)),
	}
	xs := C.struct_ConstBytes{
		data: (*C.uchar)(unsafe.Pointer(&x_s[0])),
		len:  C.int(len(x_s)),
	}
	var ret C.struct_ConstBytes

	C.ProveWrapper(hash, xs, C.uint64_t(discriminant_size_bits), C.uint64_t(num_iterations), &ret)

	if ret.len != 0 {
		defer C.free(unsafe.Pointer(ret.data))
		return C.GoBytes(unsafe.Pointer(ret.data), ret.len)
	} else {
		return nil
	}
}
