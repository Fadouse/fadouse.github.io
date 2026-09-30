+++
title = "Hello World"
date = 2026-09-29
slug = "helloworld"
description = "A small beginning. Familiar programs, a few languages, and a place to test how words and code live together."
tags = ["hello-world", "test"]
lang = "en"
draft = false
+++

Every new space starts somewhere. This one starts with two familiar words:
**Hello, world.**

This article is a reading and rendering sample. It brings together small programs,
public tutorial examples, and the ordinary details of a Markdown page.

## A first program

The simplest Rust program needs a function and something to say. This example comes
from [The Rust Programming Language](https://doc.rust-lang.org/book/ch01-02-hello-world.html).

```rust
fn main() {
    println!("Hello, world!");
}
```

Save it as `main.rs`, compile it, and run the result:

```bash
rustc main.rs
./main
```

```text
Hello, world!
```

## The same greeting, different languages

### Python

```python
def greet(name: str) -> str:
    return f"Hello, {name}!"


print(greet("world"))
```

### JavaScript

```javascript
function greet(name) {
  return `Hello, ${name}!`;
}

console.log(greet("world"));
```

### C

```c
#include <stdio.h>

int main(void) {
    printf("Hello, world!\n");
    return 0;
}
```

### Bash

```bash
printf '%s\n' 'Hello, world!'
```

### Zig

```zig
const std = @import("std");

pub fn main() void {
    std.debug.print("Hello, world!\n", .{});
}
```

### Java

```java
public class Main {
    public static void main(String[] args) {
        System.out.println("Hello, world!");
    }
}
```

### C++

```cpp
#include <iostream>

int main() {
    std::cout << "Hello, world!\n";
    return 0;
}
```

### Assembly

This example uses GNU assembler Intel syntax on x86-64 Linux.

```asm
.intel_syntax noprefix
.section .rodata
message:
    .ascii "Hello, world!\n"

.section .text
.global _start
_start:
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + message]
    mov edx, 14
    syscall

    mov eax, 60
    xor edi, edi
    syscall
```

## A little more than hello

The [Python tutorial](https://docs.python.org/3/tutorial/introduction.html#first-steps-towards-programming)
uses the Fibonacci sequence to introduce assignment and loops. The following short
adaptation keeps the state visible and the output easy to check. Python documentation
examples are available under the Zero Clause BSD license.

```python
current, following = 0, 1

while current < 10:
    print(current)
    current, following = following, current + following
```

The greeting function below is adapted from the
[MDN JavaScript introduction](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Introduction#getting_started_with_javascript).
It writes to the console so the example does not need a dialog.

```javascript
function greetMe(yourName) {
  console.log(`Hello ${yourName}`);
}

greetMe("World");
```

## Reading details

A sentence can contain **emphasis**, *a quieter aside*, ~~an old idea~~, and
`inline code`. A link should remain easy to recognize without taking attention
away from the words around it.

> A short quotation gives a paragraph room to breathe.
>
> This is sample text written for this page.

### A small table

| Language | Entry point | Greeting |
| --- | --- | --- |
| Rust | `fn main()` | `println!` |
| Python | Module execution | `print` |
| JavaScript | Script execution | `console.log` |
| C | `int main(void)` | `printf` |
| Bash | Script execution | `printf` |
| Zig | `pub fn main()` | `std.debug.print` |
| Java | `public static void main` | `System.out.println` |
| C++ | `int main()` | `std::cout` |
| Assembly | `_start` | Linux `write` syscall |

### Lists and tasks

1. Read the example.
2. Copy the code.
3. Run it in a suitable local environment.

- Keep functions small.
- Give values useful names.
  - Let indentation show the structure.
  - Explain a decision when a comment helps.

- [x] A first article
- [x] Examples in several languages
- [ ] More things to write

### A long line

The following line is deliberately long. It should scroll inside its code block
while the article remains within the page width.

```text
Hello, world! This deliberately long line keeps going so that horizontal scrolling can be checked on a narrow screen without stretching the article, moving the page edges, or reducing the code font size.
```

### Plain text

An unfamiliar language label should still produce a readable block.

```greeting
hello -> world
```

## Words beyond English

Hello, world. 你好，世界。こんにちは、世界。안녕하세요, 세계. Bonjour, le monde.

<p lang="ar" dir="rtl">مرحبًا بالعالم.</p>

Accented letters and combining marks belong in the same reading experience:
café, naïve, résumé, café. A small wave belongs here too: 👋.

## One last detail

Footnotes can carry an aside without interrupting a paragraph.[^sample]
The headings on this page also provide direct links for the table of contents.

[^sample]: This footnote is part of the Markdown rendering sample.

---

That is enough for a beginning. **Hello, world.**
