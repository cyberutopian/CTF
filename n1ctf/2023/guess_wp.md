## N1CTF 2023 guess writeup

### 出题思路

对于一道静态分析相关的CTF题目，如何兼顾题目与静态分析的相关性和选手做题时的体验感是出题时面临的最大困难。若在实战方向命题，例如要求使用静态分析进行漏洞挖掘或利用静态分析算法本身的漏洞，题目本身就具有较高的门槛，选手几乎无法通过临场学习完成题目。若在纯理论方向命题，例如开发分析算法并评估指标，往往会使题目丧失趣味性，且容易使0基础选手直接放弃题目。

本题在设计时采用了Soufflé作为背景，Soufflé是一个与datalog类似的逻辑编程语言执行引擎，在静态分析领域有广泛应用。题目要求选手阅读Soufflé的文档并理解部分执行原理，从而用技巧获得flag。由于规避了静态分析理论体系的学习，0基础选手也可能在48小时的比赛内完成题目，提高了题目的参与度和体验感，也希望本题能引发选手对于静态分析领域的学习兴趣。

### 题目分析

题目给出了一个Soufflé源文件：

```
.functor hash1(x:symbol):number
.functor hash2(x:symbol):number
.functor GETFLAG():symbol

.decl SALT(x:symbol)
//SALTS
.output SALT

.decl FLAG(x:symbol)
FLAG(@GETFLAG()).
.decl HINT(x:symbol)
HINT(substr(x,0,4)) :- FLAG(x).

.decl HASH(x:number)
HASH(@hash1(x)) :- FLAG(x).

.decl SALT_HASH1(h:number,s:symbol)
SALT_HASH1(h,s) :- h=@hash1(cat(flg,s)),FLAG(flg),SALT(s).


.decl SALT_HASH2(h:number,s:symbol)
SALT_HASH2(h,s) :- h=@hash2(cat(flg,s)),FLAG(flg),SALT(s).

.decl GUESS(x:symbol)
//GUESS
.output GUESS(attributeNames="ans")
```

题目服务器`chal.py`（部分代码省略）：

```python
# Enjoy the music :)
SALT_DICT=base64.b64decode(b'aHR0cHM6Ly95LnFxLmNvbS9uL3J5cXEvc29uZ0RldGFpbC8wMDAyOTJXNjJvODd3Rg==')

def generate_salts():
    num_salts=random.randint(1,16)
    return [bytes(random.choices(SALT_DICT,k=random.randint(16,32))) for _ in range(num_salts)]

def generate_tmpflag():
    return os.urandom(32).hex().encode()

# ...

# compile and write dl file using given salts and your guess rules
def generate_dl(salts,guesser):
    G=f'GUESS(x) :- {guesser}.'
    S='\n'.join([f'SALT("{i.decode()}").' for i in salts])
    compiled_chal=chal_template.replace('//GUESS',G).replace("//SALTS",S)
    os.truncate(chal_fd,0)
    os.pwrite(chal_fd,compiled_chal.encode(),0)

# run souffle and check your answer
def run_chal(TMPFLAG):
    cmdline=f"timeout -s KILL 1s ./souffle -D- -lhash --no-preprocessor -w {chal_path}"
    proc=subprocess.Popen(args=cmdline,shell=True,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env={"TMPFLAG":TMPFLAG})
    proc.wait()
    out=proc.stdout.read()
    prefix=b'---------------\nGUESS\nans\n===============\n'
    if not out.startswith(prefix):
        raise RuntimeError(f'Souffle error? {out}')
    out=out.removeprefix(prefix)[:64]
    if out!=TMPFLAG:
        raise RuntimeError(f"Wrong guess")
    
# check user guess rules
def check_user_rules(r:str):
    if len(r) > 300:
        raise RuntimeError("rule too looong")
    e=r.encode()
    ban_chars=b'Ff.'
    for i in e:
        if i>0x7f or i<0x20 or i in ban_chars:
            raise RuntimeError("illegal char in rule")

# how many rounds will you guess
DIFFICULTY=36

def game():
    user_rules=input("your rules?\n")
    check_user_rules(user_rules)
    for i in range(DIFFICULTY):
        generate_dl(generate_salts(),user_rules)
        run_chal(generate_tmpflag())
        print(f"guess {i} is correct")
    print("Congratulations! Here is your flag:")
    os.system("/readflag")

```

分析`chal.py`的交互代码，可以发现选手的任务是填写关系`GUESS`的推理规则，使得`x`始终为外部随机flag。Soufflé源文件共运行36次，如果`GUESS`的推理结果都正确，则输出题目flag。

Soufflé源文件中`@GETFLAG`、`@hash1`、`@hash2`为外部库函数。`@GETFLAG`用来获取每轮执行时的外部临时flag，`@hash1`和`@hash2`是字符串哈希函数。

一种比较显然的推理规则是`FLAG(x)`或`x=@GETFLAG()`，但`chal.py`要求推理规则中不能出现`Ff.`三个字符，所以选手无法直接获取flag。

另一个思路是通过关系`HINT`获取flag的前4字符，`SALT_HASH1`和`SALT_HASH2`获取`hash(flag+salt)`和`salt`，通过数学运算倒推flag。但flag过长，hash函数保留信息有限，容易证明无法通过hash和salt的组合恢复flag。

此时需要选手阅读文档，使用Soufflé引擎的特性获得flag。

在Soufflé中，所有的字符串（symbol）都存储于一个全局的symbol table中，字符串在关系数据中的表示形式是symbol table的序号（ordinal number）。当推理过程产生一个新字符串时，会尝试插入到symbol table中，获得其序号表示。需要猜测的flag是functor `GETFLAG`产生的字符串，会被插入到symbol table中。我们无法直接访问flag，但可以猜测其在symbol table中的序号。而souffle也提供了序号和字符串相互转换的功能，`x=as(<序号>,symbol)`即可推理出正确的flag，`ord(@GETFLAG())`可得到flag字符串的序号。

由于`chal.py`在每轮猜测会生成个数不同的salt，flag字符串的序号也会变化。如果将flag序号写成常数，无法通过36轮的猜测。选手的解法包括通过其他字符串的序号计算flag的序号（两者差值固定）、通过`GUESS`规则所在的行数（`__LINE__`）计算salt个数，从而算出flag的序号。

读者在自行尝试编写规则时，可能遇到两点问题，笔者也在这里进行分析。

1. 用`ord(@GETFLAG())`得到了flag的序号和`__LINE__`的关系，但直接填写`x=as(__LINE__-...,symbol)`无法得到flag。

这与Soufflé的计算优化有关。Soufflé在实际运行用户程序前，会进行一定程度的优化。其中一步优化为“移除多余关系”。如果关系`GUESS`的推理规则为`x=as(__LINE__-...,symbol)`，那么得到程序输出需要求解的关系只有`GUESS`和`SALT`。关系`FLAG`并没有被任何输出直接或间接地引用，因而被删除了。而Soufflé将外部functor返回的symbol插入symbol table的过程发生在用户程序运行时，关系`FLAG`被删除后，flag不再存在于symbol table。此时需要选手添加`GUESS`对`FLAG`的依赖关系，例如`HINT(_)`。

2. 如果规则用到了`SALT`，会导致Soufflé先输出`SALT`，再输出`GUESS`，导致`chal.py`报错。

这是Soufflé的求解策略决定的。如果规则用到了`SALT`，那么`SALT`的推理顺序要早于`GUESS`，由于`SALT`是一个需要输出的关系，所以`SALT`的求解过程也包括`SALT`的输出过程。呈现出来的结果就是先输出`SALT`的内容，再输出`GUESS`的内容。



附录：题解内容涉及的文档内容链接

调用外部库函数：https://souffle-lang.github.io/functors

symbol table实现：https://souffle-lang.github.io/implementation#symbols

symbol序号到字符串的转换：https://souffle-lang.github.io/types#type-conversion

`__LINE__`：https://souffle-lang.github.io/program#syntax-without-c-pre-processor



### 题目解法

笔者在这里给出一种自适应的解法：`x=as(range(0,20),symbol),HASH(@hash1(x)),to_string(range(0,20))!=x`，前半部分`x=as(range(0,20),symbol),HASH(@hash1(x))`假设flag的序号在区间[0,20)内，检查每个序号对应字符串的hash是否和flag hash相同。前半部分规则已经包括了完整的获得并验证flag的逻辑，但如果只包含前半部分规则，Soufflé很可能会报错退出，这是因为symbol table不一定包含20项内容，当猜测的序号越界时，Soufflé就会崩溃。因此需要后半部分规则为符号表做padding，`to_string(range(0,20))`生成20个字符串，保证symbol table至少包含20项内容，这样访问序号为0~19的符号就不会造成越界。提交`x=as(range(0,20),symbol),HASH(@hash1(x)),to_string(range(0,20))!=x`即可获得最终flag。

读者可能会对自适应解法的正确性有疑惑，padding方法是否会影响flag序号范围？答案是不会的。

Soufflé的symbol table按顺序编号。先插入的字符串序号严格小于后插入的字符串。`GUESS`的推理规则用到了关系`HASH`，而`HASH`用到了关系`FLAG`，因此应当先推理`FLAG`，再推理`HASH`，再推理`GUESS`。当推理`FLAG`时，flag内容已经被插入到symbol table中，padding的插入时间晚于flag的插入时间，因此padding的序号要严格大于flag的序号，padding只会起到防止Soufflé崩溃的作用，而不会影响flag的序号。
