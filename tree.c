/**********************************************************/
/*                                                        */
/* File: tree.c                                           */
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

/*
 * Function for tree initialization.
 *
 * @param tree Pointer to pointer to binary search tree.
 */
void bst_init (bst_node_t* tree)
{
    *tree = NULL;
}

/*
 * Function for searching the tree node in a tree by key. The found tree node
 * value is passed out in the value parameter.
 *
 * @param tree  Pointer to binary search tree.
 * @param key   Pointer to key which is searched.
 * @param value Pointer to pointer to flow node value in which is the found
 *              value passed out.
 * @return      True if a node was found in the tree, false otherwise.
 */
bool bst_search (bst_node_t tree,
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

/*
 * Function for inserting a tree node into the binary search tree.
 *
 * @param tree  Pointer to pointer to binary search tree.
 * @param key   Inserted node key.
 * @param value Inserted node value.
 * @return      Status of function processing.
 */
uint8_t bst_insert (bst_node_t* tree,
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

/*
 * The helper function for replacing the removing tree node with the rightmost child
 * of the left tree.
 *
 * @param target     A target tree node which should be replaced.
 * @param tree       Pointer to pointer to binary search tree.
 * @param keep_value The information about if free memory for tree node value
 *                   or not.
 */
void bst_replace_by_rightmost (bst_node_t target, bst_node_t* tree, bool keep_value)
{
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

/*
 * Function for removing a tree node from the binary search tree by key.
 * This function implementation is special in providing the keep_value parameter
 * which provides the information about if the flow value stored in the tree node
 * should be freed from memory or not.
 *
 * @param tree       Pointer to pointer to binary search tree.
 * @param key        Inserted node key.
 * @param keep_value The information about if free memory for tree node value
 *                   or not.
 */
void bst_delete (bst_node_t* tree, netflow_v5_key_t key, bool keep_value)
{
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

/*
 * Function for disposing of the whole binary search tree.
 *
 * @param tree Pointer to pointer to binary search tree.
 */
void bst_dispose (bst_node_t* tree)
{
    if (*tree != NULL)
    {
        bst_dispose(&((*tree)->left));
        bst_dispose(&((*tree)->right));

        free_tree_node(tree);
    }
}

/*
 * The helper function for moving a tree node from one binary search tree
 * to another one. At the same time, the node is removed from the source tree.
 *
 * @param dst_tree Destination tree into which is tree node moved.
 * @param node     Tree node which should be moved into the tree.
 * @return         Status of function processing.
 */
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

/*
 * Function for moving expired flows nodes from the tracking tree into the tree
 * which stores tree nodes to export.
 *
 * @param tree               Source tree in which is expired flows are searched.
 * @param expired_flows_tree The tree containing the expired flows to export.
 * @param actual_time_stamp  The current timestamp of the currently last
 *                           received packet.
 * @param options            Pointer to options storage.
 * @return                   Status of function processing.
 */
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
            options->active_entries_timeout->timeout_seconds) // Active timer check.
        {
            status = bst_move_node(expired_flows_tree, tree);
        }
        else if (actual_time_stamp->tv_sec - (*tree)->value->last->tv_sec >
            options->inactive_entries_timeout->timeout_seconds) // Inactive timer check.
        {
            status = bst_move_node(expired_flows_tree, tree);
        }
        else if (((*tree)->value->tcp_flags & TH_RST) ||
        ((*tree)->value->tcp_flags & TH_FIN)) // TCP flags check.
        {
            status = bst_move_node(expired_flows_tree, tree);
        }
    }

    return status;
}

/*
 * Function for finding the oldest node in the binary search tree by time value,
 * eventually by flow node id.
 *
 * This function is inspired of the following source:
 *
 * Source: https://stackoverflow.com/questions/11728191/how-to-create-a-function-that-returns-smallest-value-of-an-unordered-binary-tree
 * Author: yuri kilochek (https://stackoverflow.com/users/1554020/yuri-kilochek)
 * Date of answering: 2012-07-30
 * Edited: Zimano (https://stackoverflow.com/users/1037960/zimano)
 * Date of the editing: 2016-09-13
 *
 * @param tree
 * @param oldest_node Pointer to pointer to the storage of the oldest node
 *                    in the tree. Before the function call the oldest node
 *                    is the root node of the tree. After processing
 *                    the function it contains the oldest node in a provided
 *                    tree.
 * @return            Time of the currently oldest node in the tree due to
 *                    recursion calls.
 */
struct timeval* bst_find_oldest (bst_node_t* tree, bst_node_t* oldest_node)
{
    int comparison_status;
    struct timeval* time = NULL;
    struct timeval* compare_node_time = NULL;
    struct timeval* oldest_node_time;
    bst_node_t compare_node;
    uint64_t compare_node_id;
    uint64_t oldest_node_id;

    if (*tree != NULL)
    {
        time = (*tree)->value->first;

        compare_node = (*tree)->left;

        if (compare_node != NULL)
        {
            compare_node_time = bst_find_oldest(&(compare_node), oldest_node);
            comparison_status = compare_timeval(compare_node_time, time);

            if (comparison_status <= 0)
            {
                // Left node has smaller or equal time.
                time = compare_node_time;

                oldest_node_time = (*oldest_node)->value->first;

                comparison_status = compare_timeval(compare_node_time, oldest_node_time);

                // If the time is smaller than currently the oldest one, replace it.
                if (comparison_status < 0)
                {
                    *oldest_node = compare_node;
                }
                else if (comparison_status == 0)
                {
                    compare_node_id = compare_node->value->cache_id;
                    oldest_node_id = (*oldest_node)->value->cache_id;

                    if (compare_node_id > oldest_node_id)
                    {
                        if (compare_node_id - oldest_node_id > (UINT64_MAX >> 1))
                        {
                            // The older flow is with a higher id.
                            *oldest_node = compare_node;
                        }
                    }
                    else
                    {
                        // oldest_node_id > compare_node_id
                        if (oldest_node_id - compare_node_id <= (UINT64_MAX >> 1))
                        {
                            // The older flow is with a lower id.
                            *oldest_node = compare_node;
                        }
                    }
                }
            }
        }

        compare_node = (*tree)->right;

        if (compare_node != NULL)
        {
            compare_node_time = bst_find_oldest(&(compare_node), oldest_node);

            if (compare_timeval(compare_node_time, time) <= 0)
            {
                // Right node has smaller or equal time.
                time = compare_node_time;

                oldest_node_time = (*oldest_node)->value->first;

                comparison_status = compare_timeval(compare_node_time, oldest_node_time);

                // If the time is smaller than currently the oldest one, replace it.
                if (comparison_status < 0)
                {
                    *oldest_node = compare_node;
                }
                else if (comparison_status == 0)
                {
                    compare_node_id = compare_node->value->cache_id;
                    oldest_node_id = (*oldest_node)->value->cache_id;

                    if (compare_node_id > oldest_node_id)
                    {
                        if (compare_node_id - oldest_node_id > (UINT64_MAX >> 2))
                        {
                            // The older flow is with a higher id.
                            *oldest_node = compare_node;
                        }
                    }
                    else
                    {
                        // oldest_node_id > compare_node_id
                        if (oldest_node_id - compare_node_id <= (UINT64_MAX >> 2))
                        {
                            // The older flow is with a lower id.
                            *oldest_node = compare_node;
                        }
                    }
                }
            }
        }
    }

    return time;
}

/*
 * Function for exporting the oldest node from the tree.
 *
 * @param netflow_records Pointer to pointer to the netflow recording system.
 * @param sending_system  Pointer to pointer to the sending system.
 * @param tree            Pointer to pointer to the binary search tree.
 * @return                Status of function processing.
 */
uint8_t bst_export_oldest (netflow_recording_system_t netflow_records,
                           netflow_sending_system_t sending_system,
                           bst_node_t* tree)
{
    uint8_t status = NO_ERROR;
    bst_node_t oldest_node;

    if (*tree != NULL)
    {
        oldest_node = *tree;
        bst_find_oldest(tree, &oldest_node);

        status = export_flows(netflow_records,
                              sending_system,
                              &(oldest_node->value),
                              1);
        bst_delete(tree, oldest_node->key, false);
    }

    return status;
}

/*
 * Function for exporting all flows stored in the tree.
 *
 * @param netflow_records Pointer to pointer to the netflow recording system.
 * @param sending_system  Pointer to pointer to the sending system.
 * @param tree            Pointer to pointer to the binary search tree.
 * @return                Status of function processing.
 */
uint8_t bst_export_all (netflow_recording_system_t netflow_records,
                        netflow_sending_system_t sending_system,
                        bst_node_t* tree)
{
    uint8_t status = NO_ERROR;
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

        if (flows_number == MAX_FLOWS_NUMBER)
        {
            status = export_flows(netflow_records,
                                  sending_system,
                                  flows,
                                  flows_number);

            free_flow_values_array(flows, flows_number);
            flows_number = 0;

            if (status != NO_ERROR)
            {
                break;
            }
        }
    }

    if (flows_number > 0)
    {
        status = export_flows(netflow_records,
                              sending_system,
                              flows,
                              flows_number);

        free_flow_values_array(flows, flows_number);
    }

    if (status != NO_ERROR)
    {
        bst_dispose(tree);
    }

    return status;
}
