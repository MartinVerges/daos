//
// (C) Copyright 2021 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package main

/*
#include "util.h"

#include <daos/multihash.h>
#include <daos/compression.h>
#include <daos/cipher.h>
#include <daos/object.h>
#include <daos/cont_props.h>
*/
import "C"

import (
	"strconv"
	"testing"

	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"

	"github.com/daos-stack/daos/src/control/common"
)

func testProperty_EcCellSize(testRunner *testing.T) {
	for testingName, testData := range map[string]struct {
		SizeStr    string
		EntryBytes uint64
	}{
		"Human Minimal Entry": {
			SizeStr:    humanize.IBytes(C.DAOS_EC_CELL_MIN),
			EntryBytes: C.DAOS_EC_CELL_MIN,
		},
		"Human Default Entry": {
			SizeStr:    humanize.IBytes(C.DAOS_EC_CELL_DEF),
			EntryBytes: C.DAOS_EC_CELL_DEF,
		},
		"Human Maximal Entry": {
			SizeStr:    humanize.IBytes(C.DAOS_EC_CELL_MAX),
			EntryBytes: C.DAOS_EC_CELL_MAX,
		},
		"Bytes Minimal Entry": {
			SizeStr:    strconv.FormatUint(C.DAOS_EC_CELL_MIN, 10),
			EntryBytes: C.DAOS_EC_CELL_MIN,
		},
		"Bytes Default Entry": {
			SizeStr:    strconv.FormatUint(C.DAOS_EC_CELL_DEF, 10),
			EntryBytes: C.DAOS_EC_CELL_DEF,
		},
		"Bytes Maximal Entry": {
			SizeStr:    strconv.FormatUint(C.DAOS_EC_CELL_MAX, 10),
			EntryBytes: C.DAOS_EC_CELL_MAX,
		},
	} {
		testRunner.Run(testingName, func(testRunner *testing.T) {
			propEntry := new(C.struct_daos_prop_entry)
			err := propHdlrs[C.DAOS_PROP_ENTRY_EC_CELL_SZ].nameHdlr(nil,
				propEntry,
				testData.SizeStr)
			if err != nil {
				testRunner.Fatalf("Expected no error: %s", err.Error())
			}
			common.AssertEqual(testRunner,
				uint64(C.get_dpe_val(propEntry)),
				testData.EntryBytes,
				"Invalid EC Cell size")

			sizeStr := propHdlrs[C.DAOS_PROP_ENTRY_EC_CELL_SZ].toString(propEntry,
				C.DAOS_PROP_ENTRY_EC_CELL_SZ)
			common.AssertEqual(testRunner,
				humanize.IBytes(testData.EntryBytes),
				sizeStr,
				"Invalid EC Cell size representation")
		})
	}
}

func testProperty_EcCellSize_Errors(testRunner *testing.T) {
	for testingName, testData := range map[string]struct {
		SizeStr     string
		ExpectError error
	}{
		"Invalid integer": {
			SizeStr:     "100 Giga Bytes",
			ExpectError: errors.New("invalid EC cell size \"100 Giga Bytes\" (try N<unit>)"),
		},
		"Invalid cell size": {
			SizeStr:     "10",
			ExpectError: errors.New("invalid EC cell size 10"),
		},
	} {
		testRunner.Run(testingName, func(testRunner *testing.T) {
			propEntry := new(C.struct_daos_prop_entry)
			err := propHdlrs[C.DAOS_PROP_ENTRY_EC_CELL_SZ].nameHdlr(nil,
				propEntry,
				testData.SizeStr)
			common.CmpErr(testRunner, testData.ExpectError, err)
		})
	}

	testRunner.Run("Invalid Entry error message: nil entry", func(testRunner *testing.T) {
		sizeStr := propHdlrs[C.DAOS_PROP_ENTRY_EC_CELL_SZ].toString(nil,
			C.DAOS_PROP_ENTRY_EC_CELL_SZ)
		common.AssertEqual(testRunner,
			"property \""+C.DAOS_PROP_ENTRY_EC_CELL_SZ+"\" not found",
			sizeStr,
			"Invalid error message")
	})

	testRunner.Run("Invalid Entry error message: invalid size", func(testRunner *testing.T) {
		propEntry := new(C.struct_daos_prop_entry)
		sizeStr := propHdlrs[C.DAOS_PROP_ENTRY_EC_CELL_SZ].toString(propEntry,
			C.DAOS_PROP_ENTRY_EC_CELL_SZ)
		common.AssertEqual(testRunner,
			"invalid size 0",
			sizeStr,
			"Invalid error message")
	})

}
