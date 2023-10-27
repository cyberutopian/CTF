笔者在这里给出一种自适应的解法：`x=as(range(0,20),symbol),HASH(@hash1(x)),to_string(range(0,20))!=x`，前半部分`x=as(range(0,20),symbol),HASH(@hash1(x))`假设flag的序号在区间[0,20)内，检查每个序号对应字符串的hash是否和flag hash相同。前半部分规则已经包括了完整的获得并验证flag的逻辑，但如果只包含前半部分规则，Soufflé很可能会报错退出，这是因为symbol table不一定包含20项内容，当猜测的序号越界时，Soufflé就会崩溃。因此需要后半部分规则为符号表做padding，`to_string(range(0,20))`生成20个字符串，保证symbol table至少包含20项内容，这样访问序号为0~19的符号就不会造成越界。提交`x=as(range(0,20),symbol),HASH(@hash1(x)),to_string(range(0,20))!=x`即可获得最终flag。

读者可能会对自适应解法的正确性有疑惑，padding方法是否会影响flag序号范围？答案是不会的。

Soufflé的symbol table按顺序编号。先插入的字符串序号严格小于后插入的字符串。`GUESS`的推理规则用到了关系`HASH`，而`HASH`用到了关系`FLAG`，因此应当先推理`FLAG`，再推理`HASH`，再推理`GUESS`。当推理`FLAG`时，flag内容已经被插入到symbol table中，padding的插入时间晚于flag的插入时间，因此padding的序号要严格大于flag的序号，padding只会起到防止Soufflé崩溃的作用，而不会影响flag的序号。


### 附录：题解内容涉及的文档内容链接

调用外部库函数：https://souffle-lang.github.io/functors

symbol table实现：https://souffle-lang.github.io/implementation#symbols

symbol序号到字符串的转换：https://souffle-lang.github.io/types#type-conversion

`__LINE__`：https://souffle-lang.github.io/program#syntax-without-c-pre-processor
