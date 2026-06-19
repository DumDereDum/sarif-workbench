#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    int  id;
    char name[64];
} Node;


Node* find_node(int id) {
    return NULL;  /* stub: not found */
}


void process_node(int id) {
    Node* n = find_node(id);
    /* missing NULL check before use */
    /* next line dereferences n without checking it */
    printf("Node id: %d, name: %s\n", n->id, n->name);  /* CWE-476 */
}


int main(void) {
    process_node(42);
    return 0;
}
