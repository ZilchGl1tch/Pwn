/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "oof",
    /* First member's full name */
    "k1R4",
    /* First member's email address */
    "k1R4@1337.com",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

void *ptr = 0;
freed = 0;

size_t align(size_t size)
{
    return (size + 16 - (size%8));
}

void *search_chunk(size_t size) {
    if (freed == 0) {
        return -1;
    }
    void *prev = 0;
    void *t = ptr;
    for (int i=1;i<freed;i++) {
        if(*(size_t *)(t) == size) { 
            if (prev == 0) {
                ptr = *(int *)(t+4);
                freed --;
                return t;
                if (*(int *)(t+4) == 0) {
                    ptr = 0;
                    freed --;
                    return t;
                }
            }
            else {
                *(int *)(prev+4) = *(int *)(t+4);
                freed --;
                return t;
            }
        }
        else if (*(int *)(t+4) == 2){
            return -1;
        }
        prev = t;
        t = *(int *)(t+4);
    }
    return -1;
}

int add_chunk(void *p) {
    if (p == NULL) {
        return -1;
    }
    if (freed == 0) {
        ptr = p;
        freed = 1;
        return 0;
    }
    void *t = ptr;
    if (p < t){
        *(int *)(p+4) = t;
        ptr = p;
        return 0;   
    }
    while (1) {
        if (p >= t){
            *(int *)(p+4) = *(int *)(t+4);
            *(int *)(t+4) = p;
            freed ++;
            return 0;
        }
        else if (*(int *)(t+4) == 0) {
            *(int *)(p+4) = 0;
            *(int *)(t+4) = p;
            freed ++;
            return 0;
        }
        else {
            t = *(int *)(t+4);
        }
    }
}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    void *p = mm_malloc(64);
    *(int *)(p-4) = 0x2;
    return add_chunk(p-8);
}


void *mm_malloc(size_t size)
{
    void *chunk = search_chunk(size);
    if (chunk != -1) {
        *(int *)(chunk+4) = 0x1;
        return (void *)((char *)chunk+8);
    }

    int newsize = align(size);
    void *p = mem_sbrk(newsize);
    if (p == (void *)-1){
	   return NULL;
    }
    else {
        *(size_t *)p = size;
        *(int *)(p+4) = 0x1;
        return (void *)((char *)p+8);
    }
}


void mm_free(void *p)
{
    size_t size;
    size = *(size_t *)(p-8);
    if (*(int *)(p-4) == 0x1){
        *(int *)(p-4) = 0x2;
        memset(p,0,size);
        add_chunk(p-8);
        return;
    }
}


void *mm_realloc(void *p, size_t size)
{

    if (p == NULL){
        return mm_malloc(size);
    }
    if (size == 0){
        mm_free(p);
        return;
    }

    void *oldptr = p;
    void *newptr;
    size_t copySize;
    
    newptr = mm_malloc(size);
    if (newptr == NULL){
      return NULL;
    }
    copySize = *(size_t *)((char *)oldptr-8);
    if (size < copySize)
      copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}