'use strict'

/**
 * Categories this fork adds on top of upstream's.
 *
 * Upstream tops out around id 112 ("Artificial Intelligence"), which is a single
 * bucket for everything from a chat widget to a vector database. The categories
 * below split that up along the lines the taxonomy request asked for, so a
 * detection can say *which* kind of AI or connected-operations technology it is.
 *
 * Ids start at 200 to leave room for upstream to keep numbering upward without
 * colliding with these.
 *
 * `groups` reuses upstream's group ids:
 *   2 marketing   5 data   7 infrastructure   8 analytics
 *   9 development  11 security  16 business  17 location
 */
const EXTRA_CATEGORIES = {
    200: {
        name: 'Generative AI platforms',
        priority: 8,
        groups: [9, 16],
    },
    201: {
        name: 'AI development frameworks',
        priority: 7,
        groups: [9],
    },
    202: {
        name: 'Vector databases',
        priority: 5,
        groups: [5, 7],
    },
    203: {
        name: 'AI infrastructure',
        priority: 6,
        groups: [7, 9],
    },
    204: {
        name: 'Data platforms',
        priority: 5,
        groups: [5, 7],
    },
    205: {
        name: 'Fleet & telematics',
        priority: 6,
        groups: [16, 17],
    },
    206: {
        name: 'IoT platforms',
        priority: 6,
        groups: [7, 17],
    },
    207: {
        name: 'Cloud security',
        priority: 8,
        groups: [11],
    },
    208: {
        name: 'AI coding assistants',
        priority: 7,
        groups: [9],
    },
    209: {
        name: 'AI agents & assistants',
        priority: 8,
        groups: [16, 2],
    },
    210: {
        name: 'Workflow automation',
        priority: 7,
        groups: [9, 16],
    },
    211: {
        name: 'Observability',
        priority: 7,
        groups: [7, 8],
    },
}

module.exports = { EXTRA_CATEGORIES }
