# 高级工具与逆向专项-Ghidra工具使用-G2 WriteUp

## Ghidra使用-数据类型管理

Ghidra左下角的Data Type Manager可以新增数据类型，例如右键challenge.exe->New->Struct，命名为Node，然后添加字段，类型选择uint8_t，命名为value1，依次添加value2、index、checksum、reserved、next。

添加结构后，右键challenge.exe下的Node->New->pointer to Node，可以创建该结构的指针类型。

在反编译时，右键变量->Retype Variable，可指定变量类型为`Node *`，这样一些字段名就会自动显示为结构体的字段名，例如显示为`Node->next`，提高可读性。

## 分析

main函数首先调用`init_list`初始化链表，然后读取输入的字符串，调用`verify`函数进行验证。

`verify`函数反编译后进行初步重命名后结果如下：

```c
bool verify(char *string)
{
  int result1;
  size_t string_len;
  longlong length_count;
  uint s;
  undefined1 *p;
  bool correct;
  char buff [56];
  node *pointer;
  byte index;
  
  string_len = strlen(string);
  correct = false;
  if (string_len == 0x2a) {
                    /* 验证flag{}格式 */
    result1 = strncmp(string,"flag{",5);
    if (result1 == 0) {
      correct = false;
      if (string[0x29] == '}') {
        p = &g_output;
                    /* 清零 */
        for (length_count = 0x25; pointer = g_head, length_count != 0; length_count = length_count + -1) {
          *p = 0;
          p = p + 1;
        }
                    /* 拼接flag并校验 */
        for (; pointer != (node *)0x0; pointer = *(node **)&pointer->next) {       
          index = pointer->id;
          s = (uint)pointer->value1 + (uint)pointer->value2 + (uint)index;
          if ((pointer->checksum == (char)((char)s + (char)(s / 0xfb) * '\x05')) && (index < 0x24)) {
            (&g_output)[(int)(uint)index] = pointer->value1 ^ pointer->value2;
          }
        }
        DAT_140007064 = 0;
        snprintf(buff,0x2b,"flag{%s}",&g_output);
        result1 = strcmp(string,buff);
        correct = result1 == 0;
      }
    }
    else {
      correct = false;
    }
  }
  return correct;
}
```

结点结构体类似：

```c
struct Node {
    uint8_t  value1;    // +0x00
    uint8_t  value2;    // +0x01
    uint8_t  index;     // +0x02
    uint8_t  checksum;  // +0x03

    uint32_t reserved;  // +0x04，初始化为 0
    Node *next;         // +0x08
};
```

`g_head`，即链表的头节点，通过右键->References->Find References to g_head可以找到`init_list`函数，逻辑类似如下，向节点填充数据：

```c
void init_list(void)
{
    // g_raw 位于 0x140004040
    Node *node = (Node *)0x140007080; // node空间已静态分配

    for (int i = 0; i < 39; i++) {
        memcpy(node->data, &g_raw[i * 4], 4);
        node->reserved = 0;

        if (i != 38)
            node->next = node + 1;

        node++;
    }

    node[38].next = NULL;
    g_head = &node[0];
}
```

Ghidra中找到`g_raw`的内容，将140004040至1400040db的内容选中，右键->Copy Special->Bytes String，得到如下内容：

```
9b b6 12 68 c1 f0 06 bc 9e a6 04 4d a6 91 11 4d 57 64 09 c4 e8 89 0a 80 5c 6c 10 d8 ad cb 05 82 b0 d3 0c 94 db be 19 b7 78 1a 07 99 4e 7c 1e e8 d5 f8 0d df 5f 3a 23 bc 59 74 17 e4 3d 05 14 56 c7 a1 1f 8c 7e 4f 16 e3 34 57 1d a8 ad 99 18 63 98 ae 0b 56 65 55 ff aa 61 55 ff aa b9 db 13 ac 69 5c 02 c7 f3 c6 20 de 64 55 ff aa 20 12 00 32 6c 0d 1b 94 53 37 01 8b 4e 2a 15 8d 2c 15 22 63 12 3f 08 59 16 22 0e 46 e4 81 03 6d 7e 47 0f d4 d4 e3 1a d6 89 eb 21 9a 02 32 1c 50
```

编写脚本获取flag：

```python
# g_raw内容
raw_hex = "9b b6 12 68 c1 f0 06 bc 9e a6 04 4d a6 91 11 4d 57 64 09 c4 e8 89 0a 80 5c 6c 10 d8 ad cb 05 82 b0 d3 0c 94 db be 19 b7 78 1a 07 99 4e 7c 1e e8 d5 f8 0d df 5f 3a 23 bc 59 74 17 e4 3d 05 14 56 c7 a1 1f 8c 7e 4f 16 e3 34 57 1d a8 ad 99 18 63 98 ae 0b 56 65 55 ff aa 61 55 ff aa b9 db 13 ac 69 5c 02 c7 f3 c6 20 de 64 55 ff aa 20 12 00 32 6c 0d 1b 94 53 37 01 8b 4e 2a 15 8d 2c 15 22 63 12 3f 08 59 16 22 0e 46 e4 81 03 6d 7e 47 0f d4 d4 e3 1a d6 89 eb 21 9a 02 32 1c 50"
raw = bytes.fromhex(raw_hex)

flag = [''] * 36

for off in range(0, len(raw), 4):
    b0, b1, b2, b3 = raw[off:off + 4]
    print(f"b0: {b0}, b1: {b1}, b2: {b2}, b3: {b3}")
    # index 必须小于 0x24
    if b2 >= 0x24:
        print(f"Invalid index: {b2}, skipping...")
        continue

    # 校验条件：b3 == (b0 + b1 + b2 + 5 * ((b0 + b1 + b2) // 0xfb)) & 0xff
    s = b0 + b1 + b2
    if b3 == ((s + 5 * (s // 0xfb)) & 0xff):
        flag[b2] = chr(b0 ^ b1)
    else:
        print(f"Invalid checksum for index {b2}: b3={b3}, expected={(s + 5 * (s // 0xfb)) & 0xff}")

content = ''.join(flag)
print(f"flag{{{content}}}")
```