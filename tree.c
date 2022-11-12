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

#define __FAVOR_BSD // For Merlin server.
#include <netinet/tcp.h>
#undef __FAVOR_BSD // For Merlin server.

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

void bst_replace_by_rightmost(bst_node_t target, bst_node_t* tree, bool keep_value) {
    bst_node_t tmp;

    // Tree has node right subtree
    // (can occur only with outside call of the function).
    if ((*tree)->right == NULL)
    {
        free_netflow_key(&(target->key));

        if (!keep_value)
        {
            free_flow_node(&(target->value));
        }

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

        if (!keep_value)
        {
            free_flow_node(&(target->value));
        }

        tmp = (*tree)->right;

        target->key = tmp->key;
        target->value = tmp->value;
        (*tree)->right = tmp->left;

        free_tree_node_keep_data(&tmp);

        return;
    }

    bst_replace_by_rightmost(target, &((*tree)->right), keep_value);
}

void bst_delete(bst_node_t* tree, netflow_v5_key_t key, bool keep_value) {
    bst_node_t tmp;
    int comparison_status;

    if (*tree != NULL)
    {
        comparison_status = compare_flows((*tree)->key, key);

        if (comparison_status == 0)
        {
            if ((*tree)->left == NULL && (*tree)->right == NULL)
            {
                if (keep_value)
                {
                    free_netflow_key(&((*tree)->key));
                    free_tree_node_keep_data(tree);
                }
                else
                {
                    free_tree_node(tree);
                }
            }
            else
            {
                if ((*tree)->left != NULL && (*tree)->right != NULL)
                {
                    bst_replace_by_rightmost(*tree, &((*tree)->left), keep_value);
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

                    if (keep_value)
                    {
                        free_netflow_key(&(tmp->key));
                        free_tree_node_keep_data(&tmp);
                    }
                    else
                    {
                        free_tree_node(&tmp);
                    }
                }
            }
        }
        else
        {
            if (comparison_status > 0)
            {
                bst_delete(&((*tree)->left), key, keep_value);
            }
            else
            {
                // The comparison_status value is a negative number.
                bst_delete(&((*tree)->right), key, keep_value);
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

uint8_t bst_move_node (bst_node_t* dst_tree, bst_node_t* node)
{
    uint8_t status;
    netflow_v5_key_t flow_key;
    flow_node_t flow_value;

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

    memcpy(flow_key, (*node)->key, sizeof(*flow_key));
    memcpy(flow_value->first, (*node)->value->first, sizeof(*(flow_value->first)));
    memcpy(flow_value->last, (*node)->value->last, sizeof(*(flow_value->last)));

    flow_value->src_addr = (*node)->value->src_addr;
    flow_value->dst_addr = (*node)->value->dst_addr;
    flow_value->packets = (*node)->value->packets;
    flow_value->octets = (*node)->value->octets;
    flow_value->src_port = (*node)->value->src_port;
    flow_value->dst_port = (*node)->value->dst_port;
    flow_value->tcp_flags = (*node)->value->tcp_flags;
    flow_value->prot = (*node)->value->prot;
    flow_value->tos = (*node)->value->tos;

    // Add to the destination tree.
    status = bst_insert(dst_tree, flow_key, flow_value);

    if (status != NO_ERROR)
    {
        return status;
    }

    // Remove node from the original tree.
    bst_delete(node, (*node)->key, false);

    return NO_ERROR;
}

uint8_t bst_find_expired (bst_node_t* tree,
                          bst_node_t* expired_flows_tree,
                          struct timeval* actual_time_stamp,
                          options_t options)
{
    uint8_t status;

    status = NO_ERROR;

    if (*tree != NULL)
    {
        bst_find_expired(&((*tree)->left), expired_flows_tree, actual_time_stamp, options);
        bst_find_expired(&((*tree)->right), expired_flows_tree, actual_time_stamp, options);

        if ((actual_time_stamp->tv_sec - (*tree)->value->first->tv_sec) >
            options->active_entries_timeout->timeout_seconds) // Active timer check
        {
            printf("exporting because of ACTIVE timer\n");
            status = bst_move_node(expired_flows_tree, tree);
        }
        else if (actual_time_stamp->tv_sec - (*tree)->value->last->tv_sec >
            options->inactive_entries_timeout->timeout_seconds) // Inactive timer check
        {
            printf("exporting because of INACTIVE timer\n");
            status = bst_move_node(expired_flows_tree, tree);
        }
        else if (((*tree)->value->tcp_flags & TH_RST) ||
        ((*tree)->value->tcp_flags & TH_FIN))
        {
            printf("exporting because of TCP flags\n");
            status = bst_move_node(expired_flows_tree, tree);
        }
    }

    return status;
}

// https://stackoverflow.com/questions/11728191/how-to-create-a-function-that-returns-smallest-value-of-an-unordered-binary-tree
//struct timeval* bst_find_oldest (bst_node_t* tree, bst_node_t* oldest_node)
struct timeval* bst_find_oldest (bst_node_t* tree, bst_node_t* oldest_node)
{
    struct timeval* time = NULL;
    struct timeval* compare_node_time = NULL;
    struct timeval* oldest_node_time;
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

                oldest_node_time = (*oldest_node)->value->first;

                // If the time is smaller than currently the oldest one, replace it.
                if (compare_timeval(compare_node_time, oldest_node_time) < 0)
                {
                    *oldest_node = compare_node;
                }
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

                oldest_node_time = (*oldest_node)->value->first;

                // If the time is smaller than currently the oldest one, replace it.
                if (compare_timeval(compare_node_time, oldest_node_time) < 0)
                {
                    *oldest_node = compare_node;
                }
            }
        }
    }

    return time;
}

void bst_export_oldest (netflow_recording_system_t netflow_records,
                        netflow_sending_system_t sending_system,
                        bst_node_t* tree)
{
    bst_node_t oldest_node;

    if (*tree != NULL)
    {
        oldest_node = *tree;
        bst_find_oldest(tree, &oldest_node);

        export_flows(netflow_records,
                    sending_system,
                    &(oldest_node->value),
                    1);
        bst_delete(tree, oldest_node->key, false);
    }
}

void bst_export_all (netflow_recording_system_t netflow_records,
                     netflow_sending_system_t sending_system,
                     bst_node_t* tree)
{
    bst_node_t oldest_node;
    flow_node_t flows[MAX_FLOWS_NUMBER];
    uint16_t flows_number = 0;

    while (*tree != NULL)
    {
        oldest_node = *tree;
        bst_find_oldest(tree, &oldest_node);

        flows[flows_number] = oldest_node->value;
        flows_number++;

        bst_delete(tree, oldest_node->key, true);

        if (flows[flows_number-1] == NULL)
        {
            printf("IS NULL\n");
        }

        if (flows_number == MAX_FLOWS_NUMBER)
        {
            export_flows(netflow_records,
                         sending_system,
                         flows,
                         flows_number);

            free_flow_values_array(flows, flows_number);
            flows_number = 0;
        }
    }

    if (flows_number > 0)
    {
        export_flows(netflow_records,
                     sending_system,
                     flows,
                     flows_number);

        free_flow_values_array(flows, flows_number);
    }
}
