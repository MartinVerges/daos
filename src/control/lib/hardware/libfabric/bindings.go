//
// (C) Copyright 2021-2022 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package libfabric

/*
#include <stdlib.h>
#include <stdio.h>
#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#define getHFIUnitError -2
typedef struct {
	uint64_t reserved_1;
	uint8_t  reserved_2;
	int8_t   unit;
	uint8_t  port;
	uint8_t  reserved_3;
	uint32_t service;
} psmx2_ep_name;

int get_hfi_unit(void *src_addr) {
	psmx2_ep_name *psmx2;
	psmx2 = (psmx2_ep_name *)src_addr;
	if (!psmx2)
		return getHFIUnitError;
	return psmx2->unit;
}

// Major and minor versions are hard-coded per libfabric recommendations
uint lib_fabric_version(void)
{
	return FI_VERSION(1, 7);
}

// calls into dynamically linked C functions

int call_getinfo(void *fn, struct fi_info *hint, struct fi_info **info)
{
	int (*fi_getinfo)(uint, char*, char*, ulong, struct fi_info*, struct fi_info**);

	fi_getinfo = (int (*)(uint, char*, char*, ulong, struct fi_info*, struct fi_info**))fn;
	return fi_getinfo(lib_fabric_version(), NULL, NULL, 0, hint, info);
}

struct fi_info *call_dupinfo(void *fn, struct fi_info *info)
{
	struct fi_info *(*fi_dupinfo)(struct fi_info*);

	fi_dupinfo = (struct fi_info *(*)(struct fi_info*))fn;
	return fi_dupinfo(info);
}

void call_freeinfo(void *fn, struct fi_info *info)
{
	void (*fi_freeinfo)(struct fi_info*);

	fi_freeinfo = (void (*)(struct fi_info*))fn;
	fi_freeinfo(info);
}

char *call_strerror(void *fn, int code)
{
	char *(*fi_strerror)(int);

	fi_strerror = (char *(*)(int))fn;
	return fi_strerror(code);
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/coreos/pkg/dlopen"
	"github.com/pkg/errors"
)

func openLib() (*dlopen.LibHandle, error) {
	return dlopen.GetHandle([]string{"libfabric.so", "libfabric.so.1"})
}

func libFabricVersion() C.uint {
	return C.lib_fabric_version()
}

var errHFIUnitsInUse = errors.New("all HFI units in use")

type fiInfo struct {
	cFI *C.struct_fi_info
}

func (f *fiInfo) domainName() string {
	if f.cFI == nil || f.cFI.domain_attr == nil || f.cFI.domain_attr.name == nil {
		return ""
	}
	return C.GoString(f.cFI.domain_attr.name)
}

func (f *fiInfo) fabricProvider() string {
	if f.cFI == nil || f.cFI.fabric_attr == nil || f.cFI.fabric_attr.prov_name == nil {
		return ""
	}
	return C.GoString(f.cFI.fabric_attr.prov_name)
}

func (f *fiInfo) hfiUnit() (uint, error) {
	hfiUnit := C.get_hfi_unit(f.cFI.src_addr)
	switch hfiUnit {
	case C.getHFIUnitError:
		return 0, errors.New("failed to get HFI unit")
	case -1:
		return 0, errHFIUnitsInUse
	}
	return uint(hfiUnit), nil
}

// fiGetInfo fetches the list of fi_info structs with the desired provider (if non-empty), or all of
// them otherwise. It also returns the cleanup function to free the fi_info.
func fiGetInfo(provider string) ([]*fiInfo, func() error, error) {
	hdl, err := openLib()
	if err != nil {
		return nil, nil, err
	}
	defer hdl.Close()

	hint, freeHint, err := fiAllocInfo(hdl)
	if err != nil {
		return nil, nil, err
	}
	defer freeHint()

	if provider != "" {
		hint.fabric_attr.prov_name = C.CString(provider)
	}

	getInfoPtr, err := getLibFuncPtr(hdl, "fi_getinfo")
	if err != nil {
		return nil, nil, err
	}

	var fi *C.struct_fi_info
	result := C.call_getinfo(getInfoPtr, hint, &fi)
	if result < 0 {
		return nil, nil, errors.Errorf("fi_getinfo() failed: %s", fiStrError(hdl, -result))
	}
	if fi == nil {
		return nil, nil, errors.Errorf("fi_getinfo() returned no results for provider %q", provider)
	}

	fiList := make([]*fiInfo, 0)
	for ; fi != nil; fi = fi.next {
		fiList = append(fiList, &fiInfo{
			cFI: fi,
		})
	}

	return fiList, func() error {
		return fiFreeInfoNoHandle(fi)
	}, nil
}

func fiAllocInfo(hdl *dlopen.LibHandle) (*C.struct_fi_info, func(), error) {
	dupPtr, err := getLibFuncPtr(hdl, "fi_dupinfo")
	if err != nil {
		return nil, nil, err
	}

	freePtr, err := getLibFuncPtr(hdl, "fi_freeinfo")
	if err != nil {
		return nil, nil, err
	}

	result := C.call_dupinfo(dupPtr, nil)
	if result == nil {
		return nil, nil, errors.New("fi_dupinfo() failed")
	}

	return result, func() {
		C.call_freeinfo(freePtr, result)
	}, nil
}

func fiStrError(hdl *dlopen.LibHandle, result C.int) string {
	ptr, err := getLibFuncPtr(hdl, "fi_strerror")
	if err != nil {
		return fmt.Sprintf("%d (%s)", result, err.Error())
	}

	cStr := C.call_strerror(ptr, -result)
	return C.GoString(cStr)
}

func fiFreeInfoNoHandle(info *C.struct_fi_info) error {
	hdl, err := openLib()
	if err != nil {
		return err
	}
	defer hdl.Close()

	ptr, err := getLibFuncPtr(hdl, "fi_freeinfo")
	if err != nil {
		return err
	}

	C.call_freeinfo(ptr, info)
	return nil
}

func getLibFuncPtr(hdl *dlopen.LibHandle, fnName string) (unsafe.Pointer, error) {
	fnPtr, err := hdl.GetSymbolPointer(fnName)
	if err != nil {
		return nil, err
	}

	if fnPtr == nil {
		return nil, errors.Errorf("%q is nil", fnName)
	}

	return fnPtr, nil
}
