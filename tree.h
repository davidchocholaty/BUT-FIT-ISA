/**********************************************************/
/*                                                        */
/* File: tree.h                                           */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Header file for binary search tree        */
/*                                                        */
/**********************************************************/

#ifndef FLOW_TREE_H
#define FLOW_TREE_H

#include <stdbool.h>
#include <stdint.h>

#include "netflow_v5.h"
#include "option.h"

struct netflow_v5_key; // Forward declaration
struct netflow_recording_system; // Forward declaration
struct netflow_sending_system; // Forward declaration

typedef struct bst_node* bst_node_t;

/*
 * Structure to store a binary search tree node.
 */
struct bst_node
{
    struct netflow_v5_key* key;
    struct flow_node* value;
    struct bst_node* left;
    struct bst_node* right;
};

/*
 * Function for tree initialization.
 *
 * @param tree Pointer to pointer to binary search tree.
 */
void bst_init (bst_node_t* tree);

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
                 struct netflow_v5_key* key,
                 struct flow_node** value);

/*
 * Function for inserting a tree node into the binary search tree.
 *
 * @param tree  Pointer to pointer to binary search tree.
 * @param key   Inserted node key.
 * @param value Inserted node value.
 * @return      Status of function processing.
 */
uint8_t bst_insert (bst_node_t* tree,
                    struct netflow_v5_key* key,
                    struct flow_node* value);

/*
 * The helper function for replacing the removing tree node with the rightmost child
 * of the left tree.
 *
 * @param target     A target tree node which should be replaced.
 * @param tree       Pointer to pointer to binary search tree.
 * @param keep_value The information about if free memory for tree node value
 *                   or not.
 */
void bst_replace_by_rightmost (bst_node_t target, bst_node_t* tree, bool keep_value);

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
void bst_delete (bst_node_t* tree, struct netflow_v5_key* key, bool keep_value);

/*
 * Function for disposing of the whole binary search tree.
 *
 * @param tree Pointer to pointer to binary search tree.
 */
void bst_dispose (bst_node_t* tree);

/*
 * The helper function for moving a tree node from one binary search tree
 * to another one. At the same time, the node is removed from the source tree.
 *
 * @param dst_tree Destination tree into which is tree node moved.
 * @param node     Tree node which should be moved into the tree.
 * @return         Status of function processing.
 */
uint8_t bst_move_node (bst_node_t* dst_tree, bst_node_t* node);

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
                          options_t options);

/*
 * Function for finding the oldest node in the binary search tree by time value,
 * eventually by flow node id.
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
struct timeval* bst_find_oldest (bst_node_t* tree, bst_node_t* oldest_node);

/*
 * Function for exporting the oldest node from the tree.
 *
 * @param netflow_records Pointer to pointer to the netflow recording system.
 * @param sending_system  Pointer to pointer to the sending system.
 * @param tree            Pointer to pointer to the binary search tree.
 * @return                Status of function processing.
 */
uint8_t bst_export_oldest (struct netflow_recording_system* netflow_records,
                           struct netflow_sending_system* sending_system,
                           bst_node_t* tree);

/*
 * Function for exporting all flows stored in the tree.
 *
 * @param netflow_records Pointer to pointer to the netflow recording system.
 * @param sending_system  Pointer to pointer to the sending system.
 * @param tree            Pointer to pointer to the binary search tree.
 * @return                Status of function processing.
 */
uint8_t bst_export_all (struct netflow_recording_system* netflow_records,
                        struct netflow_sending_system* sending_system,
                        bst_node_t* tree);

#endif // FLOW_TREE_H
