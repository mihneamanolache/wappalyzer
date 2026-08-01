import fs from 'node:fs/promises'
import { FileBlob, SpreadsheetFile } from '@oai/artifact-tool'

const inputPath = '/Users/laptop/Downloads/AI technology_products_for_veridion_070226.xlsx'
const outputPath = '/tmp/wappalyzer-workbook-rows.json'

const workbook = await SpreadsheetFile.importXlsx(await FileBlob.load(inputPath))
const summary = await workbook.inspect({
    kind: 'workbook,sheet,table',
    maxChars: 8000,
    tableMaxRows: 5,
    tableMaxCols: 8,
    tableMaxCellChars: 120,
})
const styles = await workbook.inspect({
    kind: 'computedStyle',
    sheetId: 'AI Product List',
    range: 'A1:E6',
    maxChars: 6000,
})

const products = workbook.worksheets
    .getItem('AI Product List')
    .getRange('A1:E403').values
    .slice(1)
    .filter((row) => row.some((value) => value !== null && value !== ''))
    .map(([product, vendor, vendorUrl, existsInSheet1, vendorInSheet1]) => ({
        product,
        vendor,
        vendorUrl,
        existsInSheet1,
        vendorInSheet1,
    }))

const priorities = workbook.worksheets
    .getItem('2 Priorities')
    .getRange('A1:A2')
    .values
    .flat()
    .filter(Boolean)

const categories = workbook.worksheets
    .getItem('Categories to Track')
    .getRange('A1:A7')
    .values
    .flat()
    .filter(Boolean)

await fs.writeFile(
    outputPath,
    JSON.stringify({ products, priorities, categories, summary: summary.ndjson, styles: styles.ndjson }, null, 2)
)
console.log(JSON.stringify({ outputPath, productCount: products.length, priorities, categories, summary: summary.ndjson, styles: styles.ndjson }))
