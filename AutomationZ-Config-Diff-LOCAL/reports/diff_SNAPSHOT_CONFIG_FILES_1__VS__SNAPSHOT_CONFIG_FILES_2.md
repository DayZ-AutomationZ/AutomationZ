# AutomationZ Config Diff — Diff Report

- A: `SNAPSHOT_CONFIG_FILES_1`
- B: `SNAPSHOT_CONFIG_FILES_2`
- Generated: `2025-12-18 03:13:27`

## Summary

- Added files: **0**
- Removed files: **0**
- Compared files: **5**

## File Diffs

### `_manifest.json`

```diff
--- A/_manifest.json
+++ B/_manifest.json
@@ -3,7 +3,7 @@
     "name": "AutomationZ Config Diff",

     "version": "1.0.1"

   },

-  "created": "2025-12-18 02:26:00",

+  "created": "2025-12-18 02:29:26",

   "files": [

     {

       "name": "testfile1.txt",

```

### `testmap/testfilemap1/testfile1.txt`

```diff
--- A/testmap/testfilemap1/testfile1.txt
+++ B/testmap/testfilemap1/testfile1.txt
@@ -1,11 +1,11 @@
 Example 1:

 

+Value = false

+Value = true

+Value = false

 Value = true

 Value = true

-Value = false

+Value = true

+Value = true

 Value = True

-Value = false

-Value = false

-Value = false

-Value = True

-Value = True

+Value = false
```

### `testmap/testfilemap2/testfile2.txt`

```diff
--- A/testmap/testfilemap2/testfile2.txt
+++ B/testmap/testfilemap2/testfile2.txt
@@ -1,11 +1,11 @@
 Example 2:

 

+Value = false

+Value = true

+Value = false

 Value = true

 Value = true

-Value = false

+Value = true

+Value = true

 Value = True

-Value = false

-Value = false

-Value = false

-Value = True

-Value = True
+Value = false
```

### `testmap/testfilemap3/testfile3.txt`

```diff
--- A/testmap/testfilemap3/testfile3.txt
+++ B/testmap/testfilemap3/testfile3.txt
@@ -1,11 +1,11 @@
-Example 1:

+Example 3:

 

+Value = false

+Value = true

+Value = false

 Value = true

 Value = true

-Value = false

+Value = true

+Value = true

 Value = True

-Value = false

-Value = false

-Value = false

-Value = True

-Value = True
+Value = false
```

### `testmap/testfilemap4/testfile4.txt`

```diff
--- A/testmap/testfilemap4/testfile4.txt
+++ B/testmap/testfilemap4/testfile4.txt
@@ -1,11 +1,11 @@
-Example 1:

+Example 4:

 

+Value = false

+Value = true

+Value = false

 Value = true

 Value = true

-Value = false

+Value = true

+Value = true

 Value = True

-Value = false

-Value = false

-Value = false

-Value = True

-Value = True
+Value = false
```

