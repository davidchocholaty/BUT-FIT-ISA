/**********************************************************/
/*                                                        */
/* File: tree.h                                           */
/* Created: 2022-10-31                                    */
/* Last change: 2022-11-05                                */
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
struct netflow_v5_flow_record; // Forward declaration

typedef struct bst_node* bst_node_t;

struct bst_node
{
    struct netflow_v5_key* key;
    struct netflow_v5_flow_record* value;
    struct bst_node* left;
    struct bst_node* right;
};

void bst_init(bst_node_t* tree);

bool bst_search(bst_node_t tree,
                struct netflow_v5_key* key,
                struct netflow_v5_flow_record** value);

uint8_t bst_insert(bst_node_t* tree,
                   struct netflow_v5_key* key,
                   struct netflow_v5_flow_record* value);

void bst_delete(bst_node_t* tree, struct netflow_v5_key* key);

void bst_dispose(bst_node_t* tree);


void bst_replace_by_rightmost(bst_node_t target, bst_node_t* tree);

void bst_export_expired (bst_node_t* tree,
                         struct timeval actual_time_stamp,
                         options_t options);

#endif // FLOW_TREE_H
