#!/usr/bin/env bats

@test "sudo-сессия получена до установки Homebrew для IDN-домена" {
  run bash "$BATS_TEST_DIRNAME/helpers/idn-sudo-order.sh"
  [ "$status" -eq 0 ]
}
