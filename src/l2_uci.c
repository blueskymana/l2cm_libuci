/*************************************************************************
> File Name: main.c
> Author: 
> Mail: 
> Created Time: 2017年02月08日 星期三 17时36分35秒
************************************************************************/

#include<stdio.h>
#include<string.h>
#include <uci.h>

int Uci_get(char *in, char *out)
{
    char *path = NULL;
    struct  uci_ptr ptr;
    struct  uci_context *c = NULL ;

    if (!in || !out){
        return -1;
    }
    path = in;

    c = uci_alloc_context();
    if(!c) {
        return -1;
    }

    // path 必须是数组 must be array
    if ((uci_lookup_ptr(c, &ptr, path, true) != UCI_OK) ||
        (ptr.o==NULL || ptr.o->v.string==NULL)) 
    { 
        uci_free_context(c);
        return -1;
    }

    if(ptr.flags & UCI_LOOKUP_COMPLETE)
    {
        printf("out\n");
        strcpy(out, ptr.o->v.string);
        printf("in:%s,out:%s.\n", in, ptr.o->v.string);
    }

    uci_free_context(c);

    return 0;
}

/*
 * in: eg.wireless.@wifi-iface[0].bssid='aa:bb:cc:dd:ee:11'
 */
int L2_uci_set(char *in)
{
    char *path = NULL;
    struct  uci_ptr ptr;
    struct  uci_context *c = NULL ;

    if (!in){
        return -1;
    }
    path = in;

    printf("L2_uci_set :%s\n", path);
    if (*path == 0) path++;

    c = uci_alloc_context();
    if(!c) return -1;

    if ((uci_lookup_ptr(c, &ptr, path, true) != UCI_OK) ||
        (ptr.o==NULL || ptr.o->v.string==NULL)) 
    { 
        printf("Uci_set ptr.value:%s\n", ptr.value);
        uci_free_context(c);
        return -1;
    }

    if(ptr.flags & UCI_LOOKUP_COMPLETE)
        printf("Uci_set in:%s, ptr.value:%s\n", in, ptr.value);


    if (uci_set(c, &ptr) != UCI_OK)
    {
        uci_free_context(c);
        uci_perror(c,"UCI Error");
        return;
    }

    // commit your changes to make sure that UCI values are saved
    if (uci_commit(c, &ptr.p, false) != UCI_OK)
    {
        uci_free_context(c);
        uci_perror(c,"UCI Error");
        return;
    }

    uci_free_context(c);
}

// '\na=aa\nb=bb\n'
int L2_uci_set_for(char *in)
{
    char *start = NULL;
    char *last = NULL;
    char *tmp = NULL;

    printf("L2_uci_set_for %s\n", in);
    start = strchr(in, '\n');
    while(start) {
        start++;
        last = strchr(start, '\n');
        if (last) {
            *last = 0;
            tmp = strdup(start);
            L2_uci_set(tmp);
            free(tmp);
        }
        start = last;
    }
    return 0;
}

//ubus call network reload

int Uci_set_bak(char *in, char *value)
{
    char path = NULL;
    struct  uci_ptr ptr;
    struct  uci_context *c = NULL ;

    if (!in || !value){
        return -1;
    }
    path = in;

    c = uci_alloc_context();
    if(!c) return -1;

    if ((uci_lookup_ptr(c, &ptr, path, true) != UCI_OK) ||
            (ptr.o==NULL || ptr.o->v.string==NULL)) 
    { 
        uci_free_context(c);
        return -1;
    }

    if(ptr.flags & UCI_LOOKUP_COMPLETE)
        printf("Uci_set in:%s=%s\n", in, ptr.o->v.string);


    // setting UCI values
    // -----------------------------------------------------------
    // this will set the value to 1234
    // uci_set(struct uci_context *ctx, struct uci_ptr *ptr)
    //ptr.value = "auto";
    ptr.value = value;
    if (uci_set(c, &ptr) != UCI_OK)
    {
        uci_free_context(c);
        uci_perror(c,"UCI Error");
        return;
    }

    // commit your changes to make sure that UCI values are saved
    if (uci_commit(c, &ptr.p, false) != UCI_OK)
    {
        uci_free_context(c);
        uci_perror(c,"UCI Error");
        return;
    }

    uci_free_context(c);
}

int read_cmd(char *in, char *out)
{
    FILE *file = NULL;
    int iRet = 0;
    file = popen(in, "r");
    if (file)
    {
        fread(out, 1, 5000, file);
        printf("%s\n", out);
        iRet = strlen(out);
        pclose(file);
    }
    else {
        perror("###popen");
    }

    return iRet;
}
