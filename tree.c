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
#include <string.h>

#include "error.h"
#include "memory.h"
#include "netflow_v5.h"
#include "util.h"


void bst_init(bst_node_t* tree) {
    *tree = NULL;
}

bool bst_search(bst_node_t tree,
                netflow_v5_key_t key,
                flow_node_t *value)
{
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
                   flow_node_t value)
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
        free_flow_node(&(target->value));

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
        free_flow_node(&(target->value));

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

uint8_t bst_find_expired (bst_node_t* tree,
                          bst_node_t* expired_flows_tree,
                          struct timeval* actual_time_stamp,
                          options_t options)
{
    uint8_t status;
    netflow_v5_key_t flow_key;
    flow_node_t flow_value;

    if (*tree != NULL)
    {
        // TODO exportovani od nejstarsiho zaznamu
        bst_find_expired(&((*tree)->left), expired_flows_tree, actual_time_stamp, options);
        bst_find_expired(&((*tree)->right), expired_flows_tree, actual_time_stamp, options);
/*
        if ((actual_time_stamp->tv_sec - (*tree)->value->first->tv_sec) >
            options->active_entries_timeout->timeout_seconds) // Active timer check
        {
            status = allocate_netflow_key(&flow_key);

            if (status != NO_ERROR)
            {
                return MEMORY_HANDLING_ERROR;
            }

            status = allocate_flow_node(&flow_value);

            if (status != NO_ERROR)
            {
                return MEMORY_HANDLING_ERROR;
            }

            memcpy(flow_key, (*tree)->key, sizeof(*flow_key));
            memcpy(flow_value, (*tree)->value, sizeof(*flow_value));
            memcpy(flow_value->first, (*tree)->value->first, sizeof(*(flow_value->first)));
            memcpy(flow_value->last, (*tree)->value->last, sizeof(*(flow_value->last)));

            // Add to the tree of expired flows.
            status = bst_insert(expired_flows_tree, flow_key, flow_value);

            if (status != NO_ERROR)
            {
                return status;
            }

            // Remove node from the flows tree.
            bst_delete(tree, (*tree)->key);
        }

        else*/ if (actual_time_stamp->tv_sec - (*tree)->value->last->tv_sec >
            options->inactive_entries_timeout->timeout_seconds) // Inactive timer check
        {
            status = allocate_netflow_key(&flow_key);

            if (status != NO_ERROR)
            {
                return MEMORY_HANDLING_ERROR;
            }

            status = allocate_flow_node(&flow_value);

            if (status != NO_ERROR)
            {
                return MEMORY_HANDLING_ERROR;
            }

            memcpy(flow_key, (*tree)->key, sizeof(*flow_key));
            memcpy(flow_value->first, (*tree)->value->first, sizeof(*(flow_value->first)));
            memcpy(flow_value->last, (*tree)->value->last, sizeof(*(flow_value->last)));

            flow_value->src_addr = (*tree)->value->src_addr;
            flow_value->dst_addr = (*tree)->value->dst_addr;
            flow_value->packets = (*tree)->value->packets;
            flow_value->octets = (*tree)->value->octets;
            flow_value->src_port = (*tree)->value->src_port;
            flow_value->dst_port = (*tree)->value->dst_port;
            flow_value->tcp_flags = (*tree)->value->tcp_flags;
            flow_value->prot = (*tree)->value->prot;
            flow_value->tos = (*tree)->value->tos;

            // Add to the tree of expired flows.
            status = bst_insert(expired_flows_tree, flow_key, flow_value);

            if (status != NO_ERROR)
            {
                return status;
            }

            // Remove node from the flows tree.
            bst_delete(tree, (*tree)->key);
        }

        // TODO TCP flags etc.
    }

    return NO_ERROR;
}

// https://stackoverflow.com/questions/11728191/how-to-create-a-function-that-returns-smallest-value-of-an-unordered-binary-tree
//struct timeval* bst_find_oldest (bst_node_t* tree, bst_node_t* oldest_node)
struct timeval* bst_find_oldest (bst_node_t* tree, bst_node_t* oldest_node)
{
    struct timeval* time = NULL;
    struct timeval* compare_node_time = NULL;
    bst_node_t compare_node;

    if (*tree != NULL)
    {
        time = (*tree)->value->first;

        compare_node = (*tree)->left;

        if (compare_node != NULL)
        {
            compare_node_time = bst_find_oldest(&(compare_node), oldest_node);

            if (compare_timeval(compare_node_time, time) < 0)
            {
                // Left node has smaller time.
                time = compare_node_time;
                *oldest_node = (*tree)->left;
            }
        }

        compare_node = (*tree)->right;

        if (compare_node != NULL)
        {
            compare_node_time = bst_find_oldest(&(compare_node), oldest_node);

            if (compare_timeval(compare_node_time, time) < 0)
            {
                // Right node has smaller time.
                time = compare_node_time;
                *oldest_node = (*tree)->right;
            }
        }
    }

    return time;
}

void bst_export_all (netflow_recording_system_t netflow_records,
                     netflow_sending_system_t sending_system,
                     bst_node_t* tree)
{
    bst_node_t oldest_node;

    while (*tree != NULL)
    {
        oldest_node = *tree;
        bst_find_oldest(tree, &oldest_node);

        export_flow(netflow_records,
                    sending_system,
                    oldest_node->value);
        bst_delete(tree, oldest_node->key);
    }
/*
    if (*tree != NULL)
    {
        bst_export_all(netflow_records, sending_system, &((*tree)->left));
        bst_export_all(netflow_records, sending_system, &((*tree)->right));

        export_flow(netflow_records, sending_system,  (*tree)->value);
    }
*/

}
