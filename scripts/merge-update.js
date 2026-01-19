#!/usr/bin/env node

/**
 * Script to update technologies from upstream WITHOUT losing custom technologies.
 * 
 * What it does:
 * 1. Downloads new technologies from GitHub (enthec/webappanalyzer)
 * 2. Preserves custom technologies (that don't exist in upstream)
 * 3. Updates existing technologies with versions from upstream
 * 4. Adds new technologies from upstream
 * 
 * Usage: 
 *   node scripts/merge-update.js           # Performs the actual update
 *   node scripts/merge-update.js --dry-run # Shows what it would do without modifying
 *   node scripts/merge-update.js --report  # Only difference report
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const UPSTREAM_REPO = 'https://github.com/enthec/webappanalyzer.git';
const TEMP_DIR = '/tmp/webappanalyzer_update';
const TECHNOLOGIES_DIR = path.resolve(__dirname, '../technologies');
const CATEGORIES_FILE = path.resolve(__dirname, '../categories.json');
const BACKUP_DIR = path.resolve(__dirname, '../backup');

// Parse arguments
const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const REPORT_ONLY = args.includes('--report');

// Colors for output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
};

function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

function logSection(title) {
    console.log('\n' + '='.repeat(60));
    log(title, 'cyan');
    console.log('='.repeat(60));
}

/**
 * Downloads the upstream repository to a temporary folder
 */
function downloadUpstream() {
    logSection('📥 Downloading from GitHub...');

    if (fs.existsSync(TEMP_DIR)) {
        fs.rmSync(TEMP_DIR, { recursive: true });
    }

    log(`Cloning ${UPSTREAM_REPO}...`, 'blue');
    try {
        execSync(`git clone --depth=1 ${UPSTREAM_REPO} ${TEMP_DIR}`, { stdio: 'pipe' });
        log('Download complete', 'green');
    } catch (error) {
        log(`Download error: ${error.message}`, 'red');
        process.exit(1);
    }
}

/**
 * Loads all technologies from a folder
 */
function loadTechnologies(folder) {
    const technologies = {};
    const files = fs.readdirSync(folder).filter(f => f.endsWith('.json'));

    for (const file of files) {
        const filePath = path.join(folder, file);
        try {
            const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            Object.assign(technologies, content);
        } catch (error) {
            log(`Error parsing ${file}: ${error.message}`, 'yellow');
        }
    }
    return technologies;
}

/**
 * Loads technologies by file
 */
function loadTechnologiesByFile(folder) {
    const techByFile = {};
    const files = fs.readdirSync(folder).filter(f => f.endsWith('.json'));

    for (const file of files) {
        const filePath = path.join(folder, file);
        try {
            techByFile[file] = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        } catch (error) {
            log(`Error parsing ${file}: ${error.message}`, 'yellow');
            techByFile[file] = {};
        }
    }

    return techByFile;
}

/**
 * Compares two technology objects and returns the differences
 */
function compareTechnologies(local, upstream) {
    const localNames = new Set(Object.keys(local));
    const upstreamNames = new Set(Object.keys(upstream));

    const onlyLocal = [...localNames].filter(name => !upstreamNames.has(name));
    const onlyUpstream = [...upstreamNames].filter(name => !localNames.has(name));
    const inBoth = [...localNames].filter(name => upstreamNames.has(name));

    const modified = inBoth.filter(name => {
        return JSON.stringify(local[name]) !== JSON.stringify(upstream[name]);
    });

    return { onlyLocal, onlyUpstream, inBoth, modified };
}

/**
 * Generates difference report
 */
function generateReport(diff, local, upstream) {
    logSection('Difference Report');

    console.log('\nSTATISTICS:');
    console.log(`   Total local technologies: ${Object.keys(local).length}`);
    console.log(`   Total technologies in GitHub: ${Object.keys(upstream).length}`);
    console.log(`   CUSTOM technologies (only yours): ${diff.onlyLocal.length}`);
    console.log(`   NEW technologies in GitHub: ${diff.onlyUpstream.length}`);
    console.log(`   MODIFIED technologies in GitHub: ${diff.modified.length}`);

    if (diff.onlyLocal.length > 0) {
        console.log('\nCUSTOM TECHNOLOGIES (will be PRESERVED):');
        diff.onlyLocal.slice(0, 50).forEach(name => {
            log(`   • ${name}`, 'green');
        });
        if (diff.onlyLocal.length > 50) {
            log(`   ... and ${diff.onlyLocal.length - 50} more custom technologies`, 'green');
        }
    }

    if (diff.onlyUpstream.length > 0) {
        console.log('\nNEW TECHNOLOGIES (will be ADDED):');
        diff.onlyUpstream.slice(0, 30).forEach(name => {
            log(`   • ${name}`, 'blue');
        });
        if (diff.onlyUpstream.length > 30) {
            log(`   ... and ${diff.onlyUpstream.length - 30} more new technologies`, 'blue');
        }
    }

    if (diff.modified.length > 0) {
        console.log('\nMODIFIED TECHNOLOGIES (will be UPDATED):');
        diff.modified.slice(0, 20).forEach(name => {
            log(`   • ${name}`, 'yellow');
        });
        if (diff.modified.length > 20) {
            log(`   ... and ${diff.modified.length - 20} more modified technologies`, 'yellow');
        }
    }
}

/**
 * Creates backup
 */
function createBackup() {
    logSection('Creating backup...');

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(BACKUP_DIR, `backup-${timestamp}`);

    if (!fs.existsSync(BACKUP_DIR)) {
        fs.mkdirSync(BACKUP_DIR, { recursive: true });
    }

    fs.mkdirSync(backupPath);

    const techBackupPath = path.join(backupPath, 'technologies');
    fs.mkdirSync(techBackupPath);

    const files = fs.readdirSync(TECHNOLOGIES_DIR).filter(f => f.endsWith('.json'));
    for (const file of files) {
        fs.copyFileSync(
            path.join(TECHNOLOGIES_DIR, file),
            path.join(techBackupPath, file)
        );
    }

    // Backup categories.json
    if (fs.existsSync(CATEGORIES_FILE)) {
        fs.copyFileSync(CATEGORIES_FILE, path.join(backupPath, 'categories.json'));
    }

    log(`Backup created at: ${backupPath}`, 'green');
    return backupPath;
}

/**
 * Determines in which file a technology should be
 */
function getFileForTechnology(name) {
    const firstChar = name.charAt(0).toLowerCase();
    if (/[a-z]/.test(firstChar)) {
        return `${firstChar}.json`;
    }
    return '_.json';
}

/**
 * Merges local and upstream technologies
 */
function mergeTechnologies(localByFile, upstreamByFile, diff) {
    logSection('Merging technologies...');

    const mergedByFile = {};
    const allFiles = new Set([...Object.keys(localByFile), ...Object.keys(upstreamByFile)]);

    for (const file of allFiles) {
        mergedByFile[file] = {};
    }

    // 1. Add CUSTOM technologies (local only) - THESE ARE PRESERVED
    log(`\nPreserving ${diff.onlyLocal.length} custom technologies...`, 'green');
    for (const name of diff.onlyLocal) {
        const file = getFileForTechnology(name);
        for (const [localFile, techs] of Object.entries(localByFile)) {
            if (techs[name]) {
                mergedByFile[file][name] = techs[name];
                break;
            }
        }
    }

    // 2. Add all technologies from upstream (new + updated)
    log(`Adding technologies from GitHub...`, 'blue');
    for (const [file, techs] of Object.entries(upstreamByFile)) {
        for (const [name, data] of Object.entries(techs)) {
            mergedByFile[file][name] = data;
        }
    }

    // Sort technologies in each file
    for (const file of Object.keys(mergedByFile)) {
        const sorted = {};
        const keys = Object.keys(mergedByFile[file]).sort((a, b) => 
            a.toLowerCase().localeCompare(b.toLowerCase())
        );
        for (const key of keys) {
            sorted[key] = mergedByFile[file][key];
        }
        mergedByFile[file] = sorted;
    }

    return mergedByFile;
}

/**
 * Saves technologies to files
 */
function saveTechnologies(mergedByFile) {
    logSection('Saving technologies...');

    for (const [file, techs] of Object.entries(mergedByFile)) {
        if (Object.keys(techs).length === 0) continue;

        const filePath = path.join(TECHNOLOGIES_DIR, file);
        const content = JSON.stringify(techs, null, 2);

        if (DRY_RUN) {
            log(`[DRY-RUN] Would save ${Object.keys(techs).length} technologies to ${file}`, 'yellow');
        } else {
            fs.writeFileSync(filePath, content);
            log(`Saved ${Object.keys(techs).length} technologies to ${file}`, 'green');
        }
    }
}

/**
 * Updates categories.json
 */
function updateCategories() {
    logSection('Updating categories.json...');

    const upstreamCategoriesPath = path.join(TEMP_DIR, 'src/categories.json');

    if (!fs.existsSync(upstreamCategoriesPath)) {
        log('categories.json not found in upstream', 'yellow');
        return;
    }

    if (DRY_RUN) {
        log('[DRY-RUN] Would update categories.json', 'yellow');
    } else {
        fs.copyFileSync(upstreamCategoriesPath, CATEGORIES_FILE);
        log('categories.json updated', 'green');
    }
}

/**
 * Cleans up temporary resources
 */
function cleanup() {
    if (fs.existsSync(TEMP_DIR)) {
        fs.rmSync(TEMP_DIR, { recursive: true });
    }
}

/**
 * Main
 */
async function main() {
    log('WAPPALYZER SMART UPDATE', 'magenta');
    log('Updates from GitHub PRESERVING custom technologies', 'magenta');

    if (DRY_RUN) {
        log('⚠️  DRY-RUN MODE - No changes will be made\n', 'yellow');
    }
    if (REPORT_ONLY) {
        log('REPORT MODE - Statistics only\n', 'yellow');
    }

    try {
        // 1. Download upstream
        downloadUpstream();

        // 2. Load technologies
        logSection('Loading technologies...');
        const localTechs = loadTechnologies(TECHNOLOGIES_DIR);
        const upstreamTechs = loadTechnologies(path.join(TEMP_DIR, 'src/technologies'));

        const localByFile = loadTechnologiesByFile(TECHNOLOGIES_DIR);
        const upstreamByFile = loadTechnologiesByFile(path.join(TEMP_DIR, 'src/technologies'));

        log(`Local technologies: ${Object.keys(localTechs).length}`, 'blue');
        log(`Technologies in GitHub: ${Object.keys(upstreamTechs).length}`, 'blue');

        // 3. Compare and generate report
        const diff = compareTechnologies(localTechs, upstreamTechs);
        generateReport(diff, localTechs, upstreamTechs);

        if (REPORT_ONLY) {
            log('\n Report mode - no changes made', 'green');
            cleanup();
            return;
        }

        // 4. Create backup (if not dry-run)
        if (!DRY_RUN) {
            createBackup();
        }

        // 5. Merge
        const merged = mergeTechnologies(localByFile, upstreamByFile, diff);

        // 6. Save result
        saveTechnologies(merged);

        // 7. Update categories
        updateCategories();

        // 8. Cleanup
        cleanup();

        logSection('COMPLETE');

        if (!DRY_RUN) {
            console.log('\nSUMMARY:');
            log(`   • ${diff.onlyLocal.length} custom technologies PRESERVED`, 'green');
            log(`   • ${diff.onlyUpstream.length} new technologies ADDED`, 'blue');
            log(`   • ${diff.modified.length} technologies UPDATED`, 'yellow');
            console.log('\nVerify changes and test before committing!');
        }

    } catch (error) {
        log(`\n✗ Error: ${error.message}`, 'red');
        console.error(error);
        cleanup();
        process.exit(1);
    }
}

main();
