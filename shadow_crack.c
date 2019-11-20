#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdbool.h>

#include<unistd.h>
#include<signal.h>
#include<crypt.h>


typedef struct __shadow_hash {
      char hash_id[8];
      char * hash_type;
      char salt[64];
      char * shadow_salt;
      char hash[512];
} shadow_hash;

void init() {
      printf("\x1b[?25l");
      printf("\x1b[0m");
      return;
}

void cleanexit() {
      printf("\x1b[0m");
      printf("\x1b[?25h");
      exit(0);
}

void newline(unsigned int n) {
      for(int i = 0; i < n; ++i) printf("%c", (char)0x0a);
      return;
}

bool file_exists(char file_path[]) {
      return (access(file_path, F_OK) == 0);
}

int strpos(char * string, char * substring, int offset) {
      char buffer[strlen(string)];
      strncpy(buffer, string + offset, strlen(string) - offset);
      char * pos = strstr(buffer, substring);

      return (pos?(pos - buffer + offset):-1);
}

void read_shadow(char * buffer, size_t bytes_n, const char shadow_path[]) {
      FILE * shadow_file = fopen(shadow_path, "r");
      fread(buffer, bytes_n, 1, shadow_file);
      buffer[strlen(buffer)-1] = '\0';
}

char * extract_user_hash(char * shadow_contents, char username[]) {
      char * user_hash = (char *)malloc(strlen(shadow_contents));
      int username_index = strpos(shadow_contents, username, 0);
      if (username_index == -1) return (char *)NULL;

      char c;

      for(int i = 0; i < strlen(shadow_contents); ++i) {
            c = shadow_contents[username_index + strlen(username) + 1 + i];
            if (c == '\n') break;
            user_hash[i] = c;
      }

      int ind1 = strpos(user_hash, ":", 0)+1;

      user_hash[ind1-1] = '\0';

      return user_hash;
}

void parse_user_hash(char * user_hash, shadow_hash * shdw_hash) {
      memset(shdw_hash, 0, sizeof(shdw_hash));

      int hash_id_index = strpos(user_hash, "$", 0)+1;
      int salt_index = strpos(user_hash, "$", hash_id_index)+1;
      int hash_index = strpos(user_hash, "$", salt_index)+1;

      memcpy(shdw_hash->hash_id, user_hash + hash_id_index, salt_index - hash_id_index - 1);
      memcpy(shdw_hash->salt, user_hash + salt_index, hash_index - salt_index - 1);
      memcpy(shdw_hash->hash, user_hash + hash_index, strlen(user_hash) - hash_index -1);

      return;
}

char * create_shadow_salt(int id, const char salt[]) {
      char * fmt_salt = (char *)malloc(sizeof(char) * 128);
      snprintf(fmt_salt, sizeof(char) * 128, "$%d$%s", id, salt);

      return fmt_salt;
}

int main(int argc, char ** argv) {
      init();

      signal(SIGSEGV, &cleanexit); /* Redirect Segfault to cleanup() */
      signal(SIGINT, &cleanexit);

      if (argc < 3) {
            printf("Usage $ %s <USER> <SHADOW FILE> <WORDLIST (optional)>\n", argv[0]);
            cleanexit();
      }

      newline(1);

      char * username = argv[1];
      char * shadow_path = argv[2];
      char * wordlist_path = (char *)NULL;

      bool use_dictionary_crack = false;

      bool shadow_file_exists = file_exists(shadow_path);

      if (!shadow_file_exists) {
            printf("File %s does not exist", shadow_path);
            newline(2);
            cleanexit();
      }

      if (argv[3]) {
            wordlist_path = argv[3];
            bool wordlist_exists = file_exists(wordlist_path);
            if (!wordlist_exists) {
                  printf("File %s does not exist", wordlist_path);
                  newline(2);
                  cleanexit();
            }
            use_dictionary_crack = true;
      }

      printf("Reading shadow file \033[4m%s\033[0m...\n", shadow_path);

      char shadow_contents[sizeof(char) * 8196];

      read_shadow(shadow_contents, sizeof(shadow_contents), shadow_path);

      printf("Extracting user \033[4m%s\033[0m's information:\n\n", username);

      char * user_hash = extract_user_hash(shadow_contents, username);

      shadow_hash hash;

      parse_user_hash(user_hash, &hash);

      int id = hash.hash_id[0] - '0';

      if (id == 1)      hash.hash_type = "MD5";
      else if (id == 2) hash.hash_type = "Blowfish";
      else if (id == 5) hash.hash_type = "SHA256";
      else if (id == 6) hash.hash_type = "SHA512";
      else              hash.hash_type = "Unknown";

      printf("\033[4mHash ID\033[0m    => %s\n", hash.hash_id);
      printf("\033[4mHash Type\033[0m  => %s\n", hash.hash_type);
      printf("\033[4mHash Salt\033[0m  => %s\n", hash.salt);
      printf("\033[4mHash Value\033[0m => %s\n", hash.hash);

      if(use_dictionary_crack) {
            newline(1);

            hash.shadow_salt = create_shadow_salt( id, hash.salt );

            /* BEGIN CRACKING */
            char password[256];
            FILE * wordlist_file = fopen(wordlist_path, "r");

            while ((fgets(password, sizeof(password), wordlist_file)) != NULL) {
                  password[strlen(password)-1] = '\0';
                  char * new_hash = crypt(password, hash.shadow_salt);
                  printf("\rTrying password [%15s => %s]              ", password, new_hash);
                  if (!strcmp(new_hash, user_hash)) {
                        printf("\n\n\033[01;32mPassword Found => %s\033[0m\n", password);
                        break;
                  }
            }

      }

      newline(1);

      cleanexit();
      return 0;
}
