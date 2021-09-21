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
    "k1R4@1337.hax",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/*
 *                             STRUCTURE OF A BLOCK
 * ---------------------------------------------------------------------------------
 * |         METADATA (8 Bytes)         |               USEABLE MEMORY             |
 * ---------------------------------------------------------------------------------
 * | SIZE OF |       ALLOC/FREED        | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |
 * |  BLOCK  | OR POINTER TO NEXT BLOCK | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |
 * |  (4B)   |          (4B)            | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |
 * ---------------------------------------------------------------------------------
 *
 */

#define ALLOC 0xaaaaaaaa // value of metadata for allocated block
#define FREED 0xffffffff // value of metadata for freed block

void *lst = FREED; 

/*
 * align - Aligns given size to fit block metadata and to be algined by 8 bytes.
 */

size_t align(size_t size)
{
    return (size + 16 - (size%8));
}

/*
 * split_block - Splits a block into two blocks of which one is of required size.
 */
void *split_block(void *p,size_t diff){

    if(diff == 0){
        return p; 
    }

    else{
        size_t size = *(size_t *)(p) - diff;
        void *nptr = p+size+8;
        *(size_t *)(p) = size;
        *(int *)(p+4) = nptr;
        *(size_t *)(nptr) = diff-8;
        return p;
    }
}

/*
 * comine_block - Cobmines two freed adjacent blocks.
 */
void *combine_block(void *a, void *b){

    if (*(size_t *)(a)+a+8 != b){
        return;
    }

    size_t size = *(size_t *)(a) + *(size_t *)(b) + 8;
    *(size_t *)(a) = size;
    *(int *)(a+4) = *(int *)(b+4);
    memset(b,0,8);
    return a;
}

/*
 * add_block - Adds block to linked list of freed blocks in ascending order of addresses.
 */
void add_block(void *p){

    if (lst == FREED || lst > p){
        *(int *)(p+4) = lst;
        lst = p;
        combine_block(p,lst);
        return;
    }
    else{
        void *t = lst;

        do{
            if(t < p){

                *(int *)(p+4) = *(int *)(t+4);
                *(int *)(t+4) = p;
                combine_block(t,p);
                return;

            }

            t = *(int *)(t+4);
            
            if(t == FREED){
                return;
            }
        }while(1);
    }
}

/*
 * search_block - Searches freed blocks for suitable block size and splits the block if required.
 */
void *search_block(size_t size){

    if (lst == FREED){
        return NULL;
    }
    void *t = lst;
    void *prev = 0;
    do{
        if(*(size_t *)(t) >= size){
    
            size_t diff = *(size_t *)(t)-size;
            void *next = *(int *)(t+4);
            void *a = split_block(t,diff);
            void *b = *(int *)(a+4);

            if(b != next){
                *(int *)(b+4) = next;
            }
             
            if(prev == 0){
                lst = b;
                return a;
            }
            *(int *)(prev+4) = b;
            return a;
        }
        prev = t;
        t = *(int *)(t+4);
        if(t == FREED){
            return NULL;
        }
    }while(1);
    return NULL;
}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    lst = FREED;
    void *p = mm_malloc(256);
    if (p == NULL){
        return -1;
    }
    mm_free(p);
    return 0;
}

/* 
 * mm_malloc - Allocate a block by checking for a free block of same size or incrementing the brk pointer.   
 */
void *mm_malloc(size_t size)
{
    int newsize = align(size);
    if (size == 0){
        return;
    }
    void *b = search_block(newsize);
    if(b != NULL){
        *(int *)(b+4) = ALLOC;
        return (void *)(b+8);
    }
    void *p = mem_sbrk(newsize+8);
    if (p == (void *)-1){
        return NULL;
    }
    else{
        *(size_t *)p = size;
        *(int *)(p+4) = ALLOC;
        return (void *)(p+8);
    }
}

/*
 * mm_free - Sets entire block to null bytes and adds it to the linked list of free blocks.
 */
void mm_free(void *ptr)
{
    if(*(int *)(ptr-4) != ALLOC){
        return;
    }
    else{
        *(int *)(ptr-4) = FREED;
        size_t size = *(size_t *)(ptr-8);
        memset(ptr,0,size);
        add_block(ptr-8);
    }
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    size_t ptr_size = *(size_t *)(ptr-8);
    if (size < ptr_size){
        ptr_size = size;
    }
    void *new = mm_malloc(size);
    if (new == NULL){
      return NULL;
    }
    memcpy(new,ptr,ptr_size);
    mm_free(ptr);
    return new;
}