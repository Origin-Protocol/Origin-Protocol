"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.studioStore = void 0;
const fs_1 = require("fs");
const path_1 = require("path");
const STORE_PATH = (0, path_1.resolve)(process.cwd(), 'data', 'studio-store.json');
function defaultState() {
    return {
        jobs: [],
        queue: [],
        credits: {},
        usage: {},
    };
}
function loadState() {
    try {
        if (!(0, fs_1.existsSync)(STORE_PATH)) {
            return defaultState();
        }
        const raw = (0, fs_1.readFileSync)(STORE_PATH, 'utf8');
        const parsed = JSON.parse(raw);
        return {
            jobs: Array.isArray(parsed.jobs) ? parsed.jobs : [],
            queue: Array.isArray(parsed.queue) ? parsed.queue : [],
            credits: parsed.credits && typeof parsed.credits === 'object' ? parsed.credits : {},
            usage: parsed.usage && typeof parsed.usage === 'object' ? parsed.usage : {},
        };
    }
    catch {
        return defaultState();
    }
}
function saveState(state) {
    (0, fs_1.mkdirSync)((0, path_1.dirname)(STORE_PATH), { recursive: true });
    (0, fs_1.writeFileSync)(STORE_PATH, JSON.stringify(state, null, 2), 'utf8');
}
const state = loadState();
exports.studioStore = {
    getJobs() {
        return state.jobs;
    },
    setJobs(jobs) {
        state.jobs = jobs;
        saveState(state);
    },
    getQueue() {
        return state.queue;
    },
    setQueue(queue) {
        state.queue = queue;
        saveState(state);
    },
    getCreditsRecord() {
        return state.credits;
    },
    setCreditsRecord(record) {
        state.credits = record;
        saveState(state);
    },
    getUsageRecord() {
        return state.usage;
    },
    setUsageRecord(record) {
        state.usage = record;
        saveState(state);
    },
};
//# sourceMappingURL=studioStore.js.map