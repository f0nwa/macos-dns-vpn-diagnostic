#!/usr/bin/env bats
# Цвет подсказок и описаний подбирается под фон терминала (запрос OSC 11):
# серый ANSI 90 на тёмных темах не виден.

load 'lib/extract'

setup() {
  source_fns bg_reply_is_dark detail_color
  ESC=$'\033'
}

@test "bg_reply_is_dark: тёмные и светлые фоны (4-, 2- и 1-значные компоненты)" {
  bg_reply_is_dark $'\033]11;rgb:1e1e/2a2a/3a3a\033\\'
  bg_reply_is_dark $'\033]11;rgb:00/00/00\a'
  bg_reply_is_dark $'\033]11;rgb:0/0/0\a'
  ! bg_reply_is_dark $'\033]11;rgb:ffff/ffff/ffff\033\\'
  ! bg_reply_is_dark $'\033]11;rgb:f/f/f\a'
  ! bg_reply_is_dark $'\033]11;rgb:f5f5/f5f5/f5f5\a'
}

@test "bg_reply_is_dark: пустой или чужой ответ — не считается тёмным" {
  ! bg_reply_is_dark ""
  ! bg_reply_is_dark "garbage"
}

@test "detail_color: DNS_DIAG_BG=dark -> яркий белый, light -> цвет по умолчанию, без запроса к терминалу" {
  [ "$(DNS_DIAG_BG=dark detail_color)" = $'\033[97m' ]
  [ -z "$(DNS_DIAG_BG=light detail_color)" ]
}
