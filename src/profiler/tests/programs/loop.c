#include <stdio.h>
#include <unistd.h>
void __attribute__((noinline)) func_d()
{
    while (1)
    {
    };
}
void __attribute__((noinline)) func_c()
{
    func_d();
}
void __attribute__((noinline)) func_b()
{
    func_c();
}
void __attribute__((noinline)) func_a()
{
    func_b();
}
int main()
{
    func_a();
}