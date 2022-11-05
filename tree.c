/**********************************************************/
/*                                                        */
/* File: tree.c                                           */
/* Created: 2022-10-31                                    */
/* Last change: 2022-11-05                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Binary search tree implementation         */
/*                                                        */
/**********************************************************/

#include "tree.h"

#include <stdbool.h>
#include <stdlib.h>

#include "error.h"
#include "memory.h"
#include "netflow_v5.h"


void bst_init(bst_node_t* tree) {
    *tree = NULL;
}

bool bst_search(bst_node_t tree,
                netflow_v5_key_t key,
                netflow_v5_flow_record_t *value) {
    if (tree != NULL)
    {
        if (compare_flows(tree->key, key) == 0)
        {
            *value = tree->value;
            return true;
        }

        if (compare_flows(tree->key, key) > 0)
        {
            return bst_search(tree->left, key, value);
        }

        return bst_search(tree->right, key, value);
    }

    return false;
}

uint8_t bst_insert(bst_node_t* tree,
                   netflow_v5_key_t key,
                   netflow_v5_flow_record_t value)
{
    uint8_t status = NO_ERROR;

    if (*tree == NULL)
    {
        status = allocate_tree_node(tree);

        if (status != NO_ERROR)
        {
            return MEMORY_HANDLING_ERROR;
        }

        if (*tree != NULL)
        {
            (*tree)->key = key;
            (*tree)->value = value;
            (*tree)->left = NULL;
            (*tree)->right = NULL;
        }
    }
    else
    {
        if (compare_flows((*tree)->key, key) > 0)
        {
            status = bst_insert(&((*tree)->left), key, value);
        }
        else
        {
            if (compare_flows((*tree)->key, key) < 0)
            {
                status = bst_insert(&((*tree)->right), key, value);
            }
            else
            {
                (*tree)->value = value;
            }
        }
    }

    return status;
}

void bst_replace_by_rightmost(bst_node_t target, bst_node_t* tree) {
    bst_node_t tmp;

    if (*tree != NULL && target != NULL)
    {
        if ((*tree)->right != NULL)
        {
            bst_replace_by_rightmost(target, &((*tree)->right));
        }
        else
        {
            target->key = (*tree)->key;
            target->value = (*tree)->value;
            tmp = *tree;
            *tree = (*tree)->left;
            free_tree_node(tmp);
        }
    }
}

void bst_delete(bst_node_t* tree, netflow_v5_key_t key) {
    bst_node_t tmp;

    if (*tree != NULL)
    {
        if (compare_flows((*tree)->key, key) > 0)
        {
            bst_delete(&((*tree)->left), key);
        }
        else
        {
            if (compare_flows((*tree)->key, key) < 0)
            {
                bst_delete(&((*tree)->right), key);
            }
            else
            {
                if ((*tree)->left == NULL && (*tree)->right == NULL)
                {
                    free_tree_node(*tree);
                }
                else
                {
                    if ((*tree)->left != NULL && (*tree)->right != NULL)
                    {
                        bst_replace_by_rightmost(*tree, &((*tree)->left));
                    }
                    else
                    {
                        if ((*tree)->left == NULL)
                        {
                            tmp = (*tree)->right;
                        }
                        else
                        {
                            tmp = (*tree)->left;
                        }

                        free_tree_node(*tree);
                        *tree = tmp;
                    }
                }
            }
        }
    }
}

void bst_dispose(bst_node_t* tree) {
    if (*tree != NULL)
    {
        bst_dispose(&((*tree)->left));
        bst_dispose(&((*tree)->right));

        free_tree_node(*tree);
    }
}

//------------------------------------------------

void bst_print_node(bst_node_t node) {
    static int i = 1;
    printf("tree node with flow: %d\n", i);

    i++;

    node = node;
}

void bst_preorder(bst_node_t tree) {
    if (tree != NULL)
    {
        bst_print_node(tree);
        bst_preorder(tree->left);
        bst_preorder(tree->right);
    }
}
