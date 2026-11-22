// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rutli_fuzz::fuzz("export_file", data));
