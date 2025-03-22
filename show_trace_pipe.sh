#!/bin/bash

TRACE_PIPE="/sys/kernel/debug/tracing/trace_pipe"

echo "BPFのログを監視中... Ctrl+C で終了"

if [[ ! -e "$TRACE_PIPE" ]]; then
    echo "エラー: trace_pipe が見つかりません。BPF プログラムが正しくロードされているか確認してください。"
    exit 1
fi

if [[ ! -r "$TRACE_PIPE" ]]; then
    echo "エラー: trace_pipe にアクセスするためには root 権限が必要です。"
    exit 1
fi

# Ctrl+C で終了
trap 'echo; echo "ログ監視を終了します。"; exit 0' INT

# ログの読み取りループ
while read -r line; do
    [[ -n "$line" ]] && echo "$line"
done < "$TRACE_PIPE"
