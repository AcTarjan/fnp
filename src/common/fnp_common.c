#include "fnp_common.h"

char* fnp_string_duplicate(const char* original)
{
    if (original == NULL)
    {
        return NULL;
    }
    size_t len = strlen(original);

    int allocated = len + 1;
    char* str = (char*)fnp_malloc(allocated);
    if (str != NULL)
    {
        fnp_memcpy(str, original, len);
        str[allocated - 1] = 0;
    }

    return str;
}

void fnp_string_free(char* str)
{
    if (str != NULL)
    {
        fnp_free(str);
    }
}

