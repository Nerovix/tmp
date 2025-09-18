#!/bin/sh
set -eu

# 无共同历史的 host kernel 对比脚本（只比源码，过滤噪声子树）
# 用法：
#   ./asgard_host_kernel_nohistory_diff.sh [ASG_DIR=. ] [OUTDIR=/tmp/host_kernel_nohist_YYYYmmdd_HHMMSS]
#
# 结果：
#   - 自动克隆候选上游（浅克隆），在关键子树上计算相似度，选最接近者
#   - 生成总览 diff、代码过滤 diff、关键子系统范围化 diff、Top 改动文件

ASG="${1:-$(pwd)}"
TS="$(date +%Y%m%d_%H%M%S 2>/dev/null || date +%s)"
OUT="${2:-/tmp/host_kernel_nohist_$TS}"
mkdir -p "$OUT"

# 关键子树（相似度与范围化对比都以这些为主）
SUBS="\
arch/arm64 \
virt/kvm \
drivers/iommu \
drivers/gpu/drm \
drivers/rknpu \
arch/arm64/boot/dts/rockchip \
include \
kernel \
mm \
"

# 候选上游（你可增删；第三列为分支/标签）
# 如网络慢，可先手动准备这些目录，再把 CANDS 替换为本地路径模式。
CANDS="
aosp|https://android.googlesource.com/kernel/common|android13-5.10-2022-11
aosp13|https://android.googlesource.com/kernel/common|android13-5.10
rockchip|https://github.com/rockchip-linux/kernel.git|android-5.10
khadas|https://github.com/khadas/linux.git|khadas-5.10
torvalds|https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git|v5.10
"

echo "ASGARD : $ASG"
echo "OUT    : $OUT"
echo

# —— 0) 生成 ASGARD “源码快照”（只含 git 跟踪文件；若非 git 仓库就整树复制） ——
SNAP_A="$OUT/asg_snapshot"; mkdir -p "$SNAP_A"
if (cd "$ASG" && git rev-parse --is-inside-work-tree >/dev/null 2>&1); then
  echo "[*] Export tracked files from ASGARD repo ..."
  (cd "$ASG" && git --work-tree="$SNAP_A" checkout-index -a) >/dev/null 2>&1 || true
  # 若 checkout-index 未覆盖（例如新起仓但没建索引），退回 rsync 复制源码
  if [ ! -f "$SNAP_A/Makefile" ]; then
    rsync -a --exclude ".git" --exclude "out" --exclude "build" "$ASG"/ "$SNAP_A"/
  fi
else
  echo "[*] ASG is not a git repo; copying tree (excluding .git/out/build) ..."
  rsync -a --exclude ".git" --exclude "out" --exclude "build" "$ASG"/ "$SNAP_A"/
fi

# —— 1) 准备候选上游快照并评分（文件哈希重合度） ——
best_name=""; best_dir=""; best_ratio="0.00"
echo "[*] Scoring upstream candidates by content similarity (key subtrees only):"

echo "" > "$OUT/similarity_scores.txt"

OLDIFS=$IFS; IFS='
'
for line in $CANDS; do
  name=$(echo "$line" | awk -F'|' '{print $1}')
  url=$(echo  "$line" | awk -F'|' '{print $2}')
  ref=$(echo  "$line" | awk -F'|' '{print $3}')

  work="$OUT/up_$name"
  echo "  - $name ($ref)"
  if [ -d "$work/.git" ]; then
    :
  else
    # 浅克隆指定分支/标签
    git clone --depth=1 -b "$ref" "$url" "$work" >/dev/null 2>&1 || {
      echo "    clone failed, skip $name"
      continue
    }
  fi

  # 只在关键子树上计算哈希重合度
  # 生成 (sha1  path) 列表
  asg_list="$OUT/asg_$name.lst"; up_list="$OUT/up_$name.lst"
  : > "$asg_list"; : > "$up_list"

  for sub in $SUBS; do
    [ -d "$SNAP_A/$sub" ] && (cd "$SNAP_A/$sub" && find . -type f -print0 | xargs -0 sha1sum) >> "$asg_list" || true
    [ -d "$work/$sub"   ] && (cd "$work/$sub"    && find . -type f -print0 | xargs -0 sha1sum) >> "$up_list"  || true
  done

  # 无文件则跳过
  if [ ! -s "$asg_list" ] || [ ! -s "$up_list" ]; then
    echo "    (empty subtree; skip)"
    continue
  fi

  sort "$asg_list" -o "$asg_list"; sort "$up_list" -o "$up_list"
  total=$(wc -l < "$asg_list" | tr -d ' ')
  match=$(comm -12 "$asg_list" "$up_list" | wc -l | tr -d ' ')
  ratio=$(python3 - <<PY
t=$total; m=$match
print("{:.2f}".format(100.0*m/max(t,1)))
PY
)
  echo "    total=$total  match=$match  ratio=${ratio}%"
  echo "$name $ref ${ratio}%" >> "$OUT/similarity_scores.txt"

  # 选最大比例
  # shell 中小数比较：借助 python
  bigger=$(python3 - <<PY
a=$ratio; b=$best_ratio
print(1 if float(a)>float(b) else 0)
PY
)
  if [ "$bigger" = "1" ]; then
    best_name="$name"; best_dir="$work"; best_ratio="$ratio"
  fi
done
IFS=$OLDIFS

if [ -z "$best_dir" ]; then
  echo "[!] No upstream snapshot scored successfully. Check network or candidate list."
  exit 3
fi

echo "[OK] Best upstream ~ $best_name  (similarity ~ ${best_ratio}%)"
echo "     Path: $best_dir"
echo

# —— 2) 生成“源码过滤”的全局 diff 和代码过滤 diff（去掉文档/工具等噪声） ——
SNAP_U="$OUT/up_best"; mkdir -p "$SNAP_U"
# 上游也做“源码快照”（直接 rsync 过滤 .git）
rsync -a --exclude ".git" "$best_dir"/ "$SNAP_U"/

# 代码过滤排除（文档、工具、脚本、固件、WiFi 等大头）
EXCL="--exclude=.git --exclude=Documentation --exclude=tools --exclude=scripts --exclude=firmware --exclude=drivers/net/wireless --exclude=drivers/staging"

# 全量（源码）总览
if command -v diffstat >/dev/null 2>&1; then
  diff -ruN --exclude=".git" "$SNAP_U" "$SNAP_A" | diffstat > "$OUT/diffstat_all.txt" || true
else
  diff -ruN --exclude=".git" "$SNAP_U" "$SNAP_A" > "$OUT/diffstat_all.txt" || true
fi
diff -ruN --exclude=".git" "$SNAP_U" "$SNAP_A" > "$OUT/full_all.diff" || true

# 代码过滤版
# shell 里 eval 以展开 EXCL
eval diff -ruN $EXCL "\"$SNAP_U\"" "\"$SNAP_A\"" \| diffstat ">" "\"$OUT/diffstat_code_only.txt\"" || true
eval diff -ruN $EXCL "\"$SNAP_U\"" "\"$SNAP_A\"" ">" "\"$OUT/full_code_only.diff\"" || true

# —— 3) 关键子系统范围化 diff（子树存在则比较；单边存在与 /dev/null 比） ——
for sub in $SUBS; do
  up="$SNAP_U/$sub"; as="$SNAP_A/$sub"
  tag=$(echo "$sub" | tr '/ ' '__')
  if [ -d "$up" ] && [ -d "$as" ]; then
    diff -ruN --exclude=".git" "$up" "$as" > "$OUT/diff__$tag.diff" || true
  elif [ -d "$as" ] && [ ! -e "$up" ]; then
    diff -ruN --exclude=".git" /dev/null "$as" > "$OUT/diff__$tag.diff" || true
  elif [ -d "$up" ] && [ ! -e "$as" ]; then
    diff -ruN --exclude=".git" "$up" /dev/null > "$OUT/diff__$tag.diff" || true
  fi
done

# —— 4) Top 改动文件（按补丁行数近似排序） ——
python3 - "$OUT/full_code_only.diff" "$OUT/top_changed_files.txt" <<'PY'
import sys,collections
udiff=sys.argv[1]; out=sys.argv[2]
add=collections.Counter(); sub=collections.Counter(); cur=None
with open(udiff,'r',errors='ignore') as f:
    for line in f:
        if line.startswith('+++ '):
            cur=line.strip()[4:]
        elif line.startswith('+') and not line.startswith('+++'):
            if cur: add[cur]+=1
        elif line.startswith('-') and not line.startswith('---'):
            if cur: sub[cur]+=1
tot=add+sub
with open(out,'w') as w:
    w.write("changed_lines  added  removed  file\n")
    for k,_ in tot.most_common(120):
        w.write(f"{add[k]+sub[k]:>13}  {add[k]:>5}  {sub[k]:>7}  {k}\n")
PY

# —— 5) 索引 —— 
{
  echo "# Host Kernel (no-history) Diff Report"
  echo "- ASGARD  : $ASG"
  echo "- Best UP : $best_name  (~${best_ratio}% similar)  => $best_dir"
  echo "- OUT     : $OUT"
  echo
  echo "## Similarity (key subtrees)"
  sed -n '1,200p' "$OUT/similarity_scores.txt"
  echo
  echo "## Global diffs"
  echo "- diffstat_all.txt"
  echo "- full_all.diff"
  echo "- diffstat_code_only.txt"
  echo "- full_code_only.diff"
  echo
  echo "## Subsystem diffs"
  ls -1 "$OUT"/diff__*.diff 2>/dev/null || true
  echo
  echo "## Top changed files"
  echo "- top_changed_files.txt"
} > "$OUT/README.txt"

echo
echo "[DONE] Reports => $OUT"
