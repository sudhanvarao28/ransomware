#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>

int main()
{
  FILE *fin = fopen("../../Makefile", "rb");

  if (fin == NULL)
  {
    perror("Error opening file");
    return 1; // Exit if the file couldn't be opened
  }

  const size_t buffersize = 2048;
  char buffer[buffersize];

  size_t bytes_read;
  while ((bytes_read = fread(buffer, 1, buffersize, fin)) > 0)
  {
    fwrite(buffer, 1, bytes_read, stdout);
  }
  fclose(fin);
  return 0;
}