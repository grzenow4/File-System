#include "err.h"
#include "HashMap.h"
#include "path_utils.h"
#include "Tree.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

// Numer błędu zwracany w przypadku próby przeniesienia
// folderu do własnego podfolderu.
#define ESUBF -1

struct Tree {
    HashMap* folder;
    pthread_mutex_t mutex;
    pthread_cond_t readers;
    pthread_cond_t writers;
    int rcount, wcount, rwait, wwait;
    int change;
};

static void reader_start(Tree* tree) {
    if (pthread_mutex_lock(&tree->mutex) != 0)
        syserr("lock failed");

    while ((tree->wcount > 0 || tree->wwait > 0) && tree->change >= 0) {
        tree->rwait++;
        if (pthread_cond_wait(&tree->readers, &tree->mutex) != 0)
            syserr("cond wait failed");
        tree->rwait--;
    }

    tree->change++;
    tree->rcount++;

    if (tree->change < 0) {
        if (pthread_cond_signal(&tree->readers) != 0)
            syserr("cond signal failed");
    }

    if (pthread_mutex_unlock(&tree->mutex) != 0)
        syserr("unlock failed");
}

static void reader_end(Tree* tree) {
    if (pthread_mutex_lock(&tree->mutex) != 0)
        syserr("lock failed");
    tree->rcount--;
    if (tree->rcount == 0 && tree->wwait > 0) {
        tree->change = 1;
        if (pthread_cond_signal(&tree->writers) != 0)
            syserr("cond signal failed");
    }

    if (pthread_mutex_unlock(&tree->mutex) != 0)
        syserr("unlock failed");
}

static void writer_start(Tree* tree) {
    if (pthread_mutex_lock(&tree->mutex) != 0)
        syserr("lock failed");

    while ((tree->rcount > 0 || tree->wcount > 0) && tree->change != 1) {
        tree->wwait++;
        if (pthread_cond_wait(&tree->writers, &tree->mutex) != 0)
            syserr("cond wait failed");
        tree->wwait--;
    }

    tree->change = 0;
    tree->wcount++;

    if (pthread_mutex_unlock(&tree->mutex) != 0)
        syserr("unlock failed");
}

static void writer_end(Tree* tree) {
    if (pthread_mutex_lock(&tree->mutex) != 0)
        syserr("lock failed");
    tree->wcount--;

    if (tree->rwait > 0) {
        tree->change = -tree->rwait;
        if (pthread_cond_signal(&tree->readers) != 0)
            syserr("cond signal failed");
    }
    else if (tree->wwait > 0) {
        tree->change = 1;
        if (pthread_cond_signal(&tree->writers) != 0)
            syserr("cond signal failed");
    }
    else {
        tree->change = 0;
    }

    if (pthread_mutex_unlock(&tree->mutex) != 0)
        syserr("unlock failed");
}

Tree* tree_new() {
    Tree* tree = malloc(sizeof(Tree));
    if (!tree)
        fatal("malloc failed");
    tree->folder = hmap_new();
    if (pthread_mutex_init(&tree->mutex, 0) != 0)
        syserr("mutex init failed");
    if (pthread_cond_init(&tree->readers, 0) != 0)
        syserr("cond init 1 failed");
    if (pthread_cond_init(&tree->writers, 0) != 0)
        syserr("cond init 2 failed");
    tree->rcount = tree->wcount = tree->rwait = tree->wwait = tree->change = 0;
    return tree;
}

void tree_free(Tree* tree) {
    const char* key;
    Tree* temp;
    HashMapIterator it = hmap_iterator(tree->folder);
    while (hmap_next(tree->folder, &it, &key, (void **) &temp))
        tree_free(temp);
    hmap_free(tree->folder);
    if (pthread_mutex_destroy(&tree->mutex) != 0)
        syserr("mutex destroy failed");
    if (pthread_cond_destroy(&tree->readers) != 0)
        syserr("cond destroy 1 failed");
    if (pthread_cond_destroy(&tree->writers) != 0)
        syserr("cond destroy 2 failed");
    free(tree);
}

char* tree_list(Tree* tree, const char* path) {
    if (!is_path_valid(path))
        return NULL;

    Tree* parent = tree;
    char component[MAX_FOLDER_NAME_LENGTH + 1];
    const char* subpath = path;

    reader_start(tree);

    while ((subpath = split_path(subpath, component)) != NULL) {
        tree = hmap_get(parent->folder, component);
        if (!tree) {
            reader_end(parent);
            return NULL;
        }
        reader_start(tree);
        reader_end(parent);
        parent = tree;
    }

    char* res = make_map_contents_string(tree->folder);
    reader_end(tree);
    return res;
}

int tree_create(Tree* tree, const char* path) {
    if (!is_path_valid(path))
        return EINVAL;

    Tree* parent = tree;
    char new_folder[MAX_FOLDER_NAME_LENGTH + 1];
    char* p = make_path_to_parent(path, new_folder);
    if (!p) return EEXIST;
    char component[MAX_FOLDER_NAME_LENGTH + 1];
    const char* subpath = p;

    writer_start(tree);

    while ((subpath = split_path(subpath, component)) != NULL) {
        tree = hmap_get(parent->folder, component);
        if (!tree) {
            free(p);
            writer_end(parent);
            return ENOENT;
        }
        writer_start(tree);
        writer_end(parent);
        parent = tree;
    }
    free(p);

    Tree* new_tree = tree_new();
    if (!hmap_insert(tree->folder, new_folder, new_tree)) {
        tree_free(new_tree);
        writer_end(tree);
        return EEXIST;
    }

    writer_end(tree);
    return 0;
}

int tree_remove(Tree* tree, const char* path) {
    if (!is_path_valid(path))
        return EINVAL;

    Tree* parent = tree;
    char remove_folder[MAX_FOLDER_NAME_LENGTH + 1];
    char* p = make_path_to_parent(path, remove_folder);
    if (!p) return EBUSY;
    char component[MAX_FOLDER_NAME_LENGTH + 1];
    const char* subpath = p;

    writer_start(tree);

    while ((subpath = split_path(subpath, component)) != NULL) {
        tree = hmap_get(parent->folder, component);
        if (!tree) {
            free(p);
            writer_end(parent);
            return ENOENT;
        }
        writer_start(tree);
        writer_end(parent);
        parent = tree;
    }
    free(p);

    Tree* child = hmap_get(tree->folder, remove_folder);
    if (!child) {
        writer_end(tree);
        return ENOENT;
    }
    writer_start(child);
    if (hmap_size(child->folder) > 0) {
        writer_end(tree);
        writer_end(child);
        return ENOTEMPTY;
    }

    //writer_end(child);
    tree_free(child);
    hmap_remove(tree->folder, remove_folder);
    writer_end(tree);
    return 0;
}

Tree* get_lca(Tree* tree, const char** path1, const char** path2) {
    char component1[MAX_FOLDER_NAME_LENGTH + 1];
    char component2[MAX_FOLDER_NAME_LENGTH + 1];
    const char* subpath1 = *path1;
    const char* subpath2 = *path2;
    Tree* parent = tree;

    reader_start(tree);

    while ((subpath1 = split_path(subpath1, component1)) != NULL &&
           (subpath2 = split_path(subpath2, component2)) != NULL) {
        if (strcmp(component1, component2) != 0) {
            reader_end(tree);
            return tree;
        }
        *path1 = subpath1;
        *path2 = subpath2;
        tree = hmap_get(parent->folder, component1);
        if (!tree) {
            reader_end(parent);
            return NULL;
        }
        reader_start(tree);
        reader_end(parent);
        parent = tree;
    }

    reader_end(tree);
    return tree;
}

int tree_move(Tree* tree, const char* source, const char* target) {
    if (!is_path_valid(source) || !is_path_valid(target))
        return EINVAL;
    if (strcmp(source, "/") == 0)
        return EBUSY;
    if (strcmp(target, "/") == 0)
        return EEXIST;
    if (strncmp(source, target, strlen(source)) == 0 && strcmp(source, target) != 0)
        return ESUBF;

    tree = get_lca(tree, &source, &target);
    if (!tree) return ENOENT;
    writer_start(tree);
    if (strcmp(source, "/") == 0 && strcmp(target, "/") == 0) {
        writer_end(tree);
        return 0;
    }

    Tree* parent = tree;
    Tree* source_parent = tree;
    char source_folder[MAX_FOLDER_NAME_LENGTH + 1];
    char* p_source = make_path_to_parent(source, source_folder);
    char component_source[MAX_FOLDER_NAME_LENGTH + 1];
    const char *subpath_source = p_source;

    while ((subpath_source = split_path(subpath_source, component_source)) != NULL) {
        source_parent = hmap_get(parent->folder, component_source);
        if (!source_parent) {
            free(p_source);
            writer_end(tree);
            if (parent != tree)
                writer_end(parent);
            return ENOENT;
        }
        writer_start(source_parent);
        if (parent != tree)
            writer_end(parent);
        parent = source_parent;
    }
    free(p_source);

    Tree* source_child = hmap_get(source_parent->folder, source_folder);
    if (!source_child) {
        writer_end(tree);
        if (source_parent != tree)
            writer_end(source_parent);
        return ENOENT;
    }

    parent = tree;
    Tree* target_parent = tree;
    char target_folder[MAX_FOLDER_NAME_LENGTH + 1];
    char* p_target = make_path_to_parent(target, target_folder);
    if (!p_target) {
        writer_end(tree);
        if (source_parent != tree)
            writer_end(source_parent);
        return EEXIST;
    }
    char component_target[MAX_FOLDER_NAME_LENGTH + 1];
    const char* subpath_target = p_target;

    while ((subpath_target = split_path(subpath_target, component_target)) != NULL) {
        target_parent = hmap_get(parent->folder, component_target);
        if (!target_parent) {
            free(p_target);
            writer_end(tree);
            if (source_parent != tree)
                writer_end(source_parent);
            if (parent != tree)
                writer_end(parent);
            return ENOENT;
        }
        writer_start(target_parent);
        if (parent != tree)
            writer_end(parent);
        parent = target_parent;
    }
    free(p_target);

    if (strcmp(source, target) == 0) {
        writer_end(tree);
        if (source_parent != tree)
            writer_end(source_parent);
        if (target_parent != tree)
            writer_end(target_parent);
        return 0;
    }
    if (!hmap_insert(target_parent->folder, target_folder, source_child)) {
        writer_end(tree);
        if (source_parent != tree)
            writer_end(source_parent);
        if (target_parent != tree)
            writer_end(target_parent);
        return EEXIST;
    }
    if (target_parent != tree)
        writer_end(target_parent);
    hmap_remove(source_parent->folder, source_folder);
    if (source_parent != tree)
        writer_end(source_parent);
    writer_end(tree);
    return 0;
}
