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
    int comparison_status;

    if (tree != NULL)
    {
        comparison_status = compare_flows(tree->key, key);

        if (comparison_status == 0)
        {
            *value = tree->value;
            return true;
        }

        if (comparison_status > 0)
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
    int comparison_status;
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
        comparison_status = compare_flows((*tree)->key, key);

        if (comparison_status > 0)
        {
            status = bst_insert(&((*tree)->left), key, value);
        }
        else
        {
            if (comparison_status < 0)
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

    // Tree has node right subtree
    // (can occur only with outside call of the function).
    if ((*tree)->right == NULL)
    {
        free_netflow_key(&(target->key));
        free_netflow_record(&(target->value));

        tmp = *tree;

        target->key = tmp->key;
        target->value = tmp->value;
        target->left = tmp->left;

        free_tree_node_keep_data(&tmp);

        return;

    }

    if ((*tree)->right->right == NULL)
    {
        free_netflow_key(&(target->key));
        free_netflow_record(&(target->value));

        tmp = (*tree)->right;

        target->key = tmp->key;
        target->value = tmp->value;
        (*tree)->right = tmp->left;

        free_tree_node_keep_data(&tmp);

        return;
    }

    bst_replace_by_rightmost(target, &((*tree)->right));
}

void bst_delete(bst_node_t* tree, netflow_v5_key_t key) {
    bst_node_t tmp;
    int comparison_status;

    if (*tree != NULL)
    {
        comparison_status = compare_flows((*tree)->key, key);

        if (comparison_status == 0)
        {
            if ((*tree)->left == NULL && (*tree)->right == NULL)
            {
                free_tree_node(tree);
            }
            else
            {
                if ((*tree)->left != NULL && (*tree)->right != NULL)
                {
                    bst_replace_by_rightmost(*tree, &((*tree)->left));
                }
                else
                {
                    tmp = *tree;

                    if ((*tree)->left == NULL)
                    {
                        *tree = (*tree)->right;
                    }
                    else
                    {
                        *tree = (*tree)->left;
                    }

                    free_tree_node(&tmp);
                }
            }
        }
        else
        {
            if (comparison_status > 0)
            {
                bst_delete(&((*tree)->left), key);
            }
            else
            {
                // The comparison_status value is a negative number.
                bst_delete(&((*tree)->right), key);
            }
        }
    }
}

void bst_dispose(bst_node_t* tree) {
    if (*tree != NULL)
    {
        bst_dispose(&((*tree)->left));
        bst_dispose(&((*tree)->right));

        free_tree_node(tree);
    }
}

//------------------------------------------------

void bst_export_expired (bst_node_t* tree,
                         netflow_sending_system_t sending_system,
                         struct timeval actual_time_stamp,
                         options_t options)
{
    if (*tree != NULL)
    {
        bst_export_expired(&((*tree)->left), sending_system, actual_time_stamp, options);
        bst_export_expired(&((*tree)->right), sending_system, actual_time_stamp, options);

        if ((actual_time_stamp.tv_sec - (*tree)->value->first.tv_sec) >
            options->active_entries_timeout->timeout_seconds) // Active timer check
        {
            // Flow expired because of active timer.
            export_flow((*tree)->value, sending_system);
            // Remove tree node.
            bst_delete(tree, (*tree)->key);
        }
        else if (actual_time_stamp.tv_sec - (*tree)->value->last.tv_sec >
            options->inactive_entries_timeout->timeout_seconds) // Inactive timer check
        {
            // Flow expired because of inactive timer.
            export_flow((*tree)->value, sending_system);
            // Remove tree node.
            bst_delete(tree, (*tree)->key);
        }

        // TODO TCP flags etc.
    }
}

void bst_export_all (bst_node_t* tree,
                     netflow_sending_system_t sending_system)
{
    if (*tree != NULL)
    {
        bst_export_all(&((*tree)->left), sending_system);
        bst_export_all(&((*tree)->right), sending_system);

        export_flow((*tree)->value, sending_system);
    }
}
