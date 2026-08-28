<script setup lang="ts" generic="TData">
import { FlexRender, type Row, type Table as TanStackTable } from '@tanstack/vue-table'
import { ArrowDown, ArrowUp, ChevronsUpDown, ChevronDown, ChevronLeft, ChevronRight } from '~/utils/icons'

type FixedColumn = { id: string; left: number }
type VirtualRow<T> = { row: Row<T>; expanded: boolean }

const props = withDefaults(defineProps<{
  table: TanStackTable<TData>
  label: string
  loading?: boolean
  error?: boolean
  total: number
  page: number
  pageSize: number
  height?: number
  minWidth?: number
  columnWidths?: Record<string, string>
  fixedColumns?: FixedColumn[]
  rowLabel?: (row: TData) => string
  evidence?: (row: TData) => string[]
  emptyTitle?: string
  emptyDescription?: string
}>(), {
  loading: false,
  error: false,
  height: 446,
  minWidth: 1120,
  columnWidths: () => ({}),
  fixedColumns: () => [],
  rowLabel: undefined,
  evidence: undefined,
  emptyTitle: '没有匹配结果',
  emptyDescription: '调整筛选条件后再试。',
})

const emit = defineEmits<{
  retry: []
  'row-activate': [row: TData]
  'update:page': [page: number]
  'update:page-size': [pageSize: number]
}>()

const expandedIds = ref<Set<string>>(new Set())
const rows = computed(() => props.table.getRowModel().rows)
const virtualRows = computed<VirtualRow<TData>[]>(() => rows.value.map((row) => ({ row, expanded: expandedIds.value.has(row.id) })))
const visibleColumns = computed(() => props.table.getVisibleLeafColumns())
const gridTemplate = computed(() => visibleColumns.value.map((column) => props.columnWidths[column.id] || 'minmax(104px, 1fr)').join(' '))

const { list: virtualList, containerProps, wrapperProps, scrollTo } = useVirtualList(virtualRows, {
  itemHeight: (index: number) => virtualRows.value[index]?.expanded ? 108 : 52,
  overscan: 8,
})

const pageCount = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)))
const firstVisible = computed(() => props.total === 0 ? 0 : ((props.page - 1) * props.pageSize) + 1)
const lastVisible = computed(() => Math.min(props.total, props.page * props.pageSize))

watch(rows, () => {
  expandedIds.value = new Set()
  nextTick(() => scrollTo(0))
})

function fixedColumn(id: string) {
  return props.fixedColumns.find((column) => column.id === id)
}

function fixedStyle(id: string) {
  const fixed = fixedColumn(id)
  return fixed ? { left: `${fixed.left}px` } : undefined
}

function toggleExpanded(row: Row<TData>) {
  const next = new Set(expandedIds.value)
  if (next.has(row.id)) next.delete(row.id)
  else next.add(row.id)
  expandedIds.value = next
}

function activateRow(row: Row<TData>) {
  if (props.rowLabel) emit('row-activate', row.original)
}

function ariaSort(column: ReturnType<TanStackTable<TData>['getAllColumns']>[number]) {
  const sorted = column.getIsSorted()
  return sorted === 'asc' ? 'ascending' : sorted === 'desc' ? 'descending' : 'none'
}

function sortLabel(label: string, state: false | 'asc' | 'desc') {
  return `${label}，${state === 'asc' ? '当前升序，切换为降序' : state === 'desc' ? '当前降序，取消排序' : '未排序，切换为升序'}`
}
</script>

<template>
  <section class="data-table surface-panel" :aria-label="label">
    <Skeleton v-if="loading" :rows="7" :label="`正在加载${label}`" />
    <ErrorState v-else-if="error" @retry="emit('retry')" />
    <EmptyState v-else-if="rows.length === 0" :title="emptyTitle" :description="emptyDescription" />
    <div v-else role="table" :aria-label="label" :aria-rowcount="total + 1" :aria-colcount="visibleColumns.length">
      <div class="table-viewport-config" :style="{ '--table-height': `${height}px`, '--table-min-width': `${minWidth}px` }">
      <div v-bind="containerProps" class="virtual-viewport">
        <div role="row" class="data-head" :style="{ gridTemplateColumns: gridTemplate }">
          <div
            v-for="header in table.getHeaderGroups()[0]?.headers"
            :key="header.id"
            role="columnheader"
            :aria-sort="header.column.getCanSort() ? ariaSort(header.column) : undefined"
            :class="['data-header-cell', { fixed: fixedColumn(header.column.id) }]"
            :style="fixedStyle(header.column.id)"
          >
            <button
              v-if="header.column.getCanSort()"
              type="button"
              :aria-label="sortLabel(String(header.column.columnDef.header || header.id), header.column.getIsSorted())"
              @click="header.column.toggleSorting()"
            >
              <FlexRender :render="header.column.columnDef.header" :props="header.getContext()" />
              <ArrowUp v-if="header.column.getIsSorted() === 'asc'" :size="12" aria-hidden="true" />
              <ArrowDown v-else-if="header.column.getIsSorted() === 'desc'" :size="12" aria-hidden="true" />
              <ChevronsUpDown v-else :size="11" aria-hidden="true" />
            </button>
            <FlexRender v-else :render="header.column.columnDef.header" :props="header.getContext()" />
          </div>
        </div>

        <div role="rowgroup" class="virtual-wrapper" :style="[wrapperProps.style, { minWidth: `${minWidth}px` }]">
          <div
            v-for="entry in virtualList"
            :key="entry.data.row.id"
            class="virtual-item"
            :style="{ height: `${entry.data.expanded ? 108 : 52}px` }"
          >
            <div
              role="row"
              :aria-label="rowLabel?.(entry.data.row.original)"
              :tabindex="rowLabel ? 0 : undefined"
              class="data-row"
              :style="{ gridTemplateColumns: gridTemplate }"
              @click="activateRow(entry.data.row)"
              @keydown.enter.prevent="activateRow(entry.data.row)"
              @keydown.space.prevent="activateRow(entry.data.row)"
            >
              <div
                v-for="cell in entry.data.row.getVisibleCells()"
                :key="cell.id"
                role="cell"
                :class="['data-cell', { fixed: fixedColumn(cell.column.id) }]"
                :style="fixedStyle(cell.column.id)"
              >
                <button
                  v-if="cell.column.id === 'expand'"
                  type="button"
                  class="expand-button"
                  :disabled="!evidence?.(entry.data.row.original).length"
                  :aria-label="entry.data.expanded ? '收起告警证据' : '展开告警证据'"
                  :aria-expanded="entry.data.expanded"
                  @click.stop="toggleExpanded(entry.data.row)"
                >
                  <ChevronDown :size="14" aria-hidden="true" />
                </button>
                <slot
                  v-else
                  :name="`cell-${cell.column.id}`"
                  :row="entry.data.row.original"
                  :cell="cell"
                  :value="cell.getValue()"
                >
                  <FlexRender :render="cell.column.columnDef.cell" :props="cell.getContext()" />
                </slot>
              </div>
            </div>
            <div v-if="entry.data.expanded" role="row" class="expanded-row">
              <div role="cell">
                <slot name="expanded" :row="entry.data.row.original">
                  <span>检测证据</span>
                  <ul><li v-for="item in evidence?.(entry.data.row.original)" :key="item">{{ item }}</li></ul>
                </slot>
              </div>
            </div>
          </div>
        </div>
      </div>
      </div>

      <footer class="table-footer">
        <span>显示 {{ firstVisible }}–{{ lastVisible }}，共 {{ total }} 条</span>
        <label>每页
          <select :value="pageSize" aria-label="每页显示条数" @change="emit('update:page-size', Number(($event.target as HTMLSelectElement).value))">
            <option :value="25">25</option><option :value="50">50</option><option :value="100">100</option>
          </select>
        </label>
        <div class="pagination" aria-label="分页导航">
          <button type="button" aria-label="上一页" :disabled="page <= 1" @click="emit('update:page', page - 1)"><ChevronLeft :size="14" aria-hidden="true" /></button>
          <span aria-current="page">第 {{ page }} / {{ pageCount }} 页</span>
          <button type="button" aria-label="下一页" :disabled="page >= pageCount" @click="emit('update:page', page + 1)"><ChevronRight :size="14" aria-hidden="true" /></button>
        </div>
      </footer>
    </div>
  </section>
</template>

<style scoped>
.data-table { overflow: hidden; }
.table-viewport-config { min-width: 0; }
.virtual-viewport { position: relative; height: var(--table-height); overflow: auto; }
.data-head, .data-row { display: grid; min-width: var(--table-min-width); }
.data-head { position: sticky; z-index: 20; top: 0; min-height: 34px; background: var(--surface-2); border-bottom: 1px solid var(--border-default); }
.data-header-cell { display: flex; align-items: center; min-width: 0; padding: 0 9px; color: var(--text-tertiary); font-size:13px; font-weight: 650; white-space: nowrap; }
.data-header-cell button { display: flex; align-items: center; justify-content: space-between; gap: 5px; width: 100%; height: 30px; padding: 0; border: 0; background: transparent; color: inherit; cursor: pointer; text-align: left; }
.data-header-cell button:hover { color: var(--text-primary); }
.virtual-wrapper { position: relative; }
.virtual-item { min-width: var(--table-min-width); }
.data-row { min-height: 52px; border-bottom: 1px solid var(--border-subtle); cursor: pointer; }
.data-row:hover, .data-row:focus-visible { background: var(--surface-2); }
.data-cell { display: flex; align-items: center; min-width: 0; padding: 5px 9px; overflow: hidden; color: var(--text-secondary); font-size:13px; white-space: nowrap; }
.data-header-cell.fixed, .data-cell.fixed { position: sticky; z-index: 6; background: var(--surface-1); box-shadow: 1px 0 var(--border-subtle); }
.data-header-cell.fixed { z-index: 24; background: var(--surface-2); }
.data-row:hover .data-cell.fixed, .data-row:focus-visible .data-cell.fixed { background: var(--surface-2); }
.expand-button { display: grid; width: 27px; height: 27px; place-items: center; border: 1px solid var(--border-subtle); border-radius: 6px; background: var(--surface-2); color: var(--text-tertiary); cursor: pointer; transition: color 140ms ease, border-color 140ms ease; }
.expand-button[aria-expanded='true'] svg { transform: rotate(180deg); }.expand-button:disabled { cursor: not-allowed; opacity: .35; }
.expanded-row { min-width: var(--table-min-width); height: 56px; padding: 8px 12px 8px 121px; border-bottom: 1px solid var(--border-default); background: color-mix(in srgb, var(--accent) 4%, var(--surface-2)); animation: expanded-in 160ms ease; }
.expanded-row > div { display: flex; align-items: flex-start; gap: 12px; color: var(--text-tertiary); font-size:13px; }.expanded-row span { flex: 0 0 auto; color: var(--accent-strong); font-weight: 650; }.expanded-row ul { display: flex; flex-wrap: wrap; gap: 4px 18px; margin: 0; padding: 0; list-style: none; }.expanded-row li::before { margin-right: 5px; color: var(--status-success); content: '✓'; }
.table-footer { display: grid; grid-template-columns: 1fr auto auto; gap: 14px; align-items: center; min-height: 42px; padding: 0 11px; border-top: 1px solid var(--border-subtle); background: var(--surface-2); color: var(--text-tertiary); font-size:13px; }
.table-footer label { display: flex; align-items: center; gap: 5px; }.table-footer select { height: 26px; border: 1px solid var(--border-default); border-radius: 5px; background: var(--surface-1); color: var(--text-secondary); font-size:13px; }
.pagination { display: flex; gap: 6px; align-items: center; }.pagination button { display: grid; width: 27px; height: 27px; place-items: center; border: 1px solid var(--border-default); border-radius: 5px; background: var(--surface-1); color: var(--text-secondary); cursor: pointer; }.pagination button:disabled { color: var(--text-disabled); cursor: not-allowed; opacity: .55; }.pagination span { min-width: 76px; text-align: center; }
@keyframes expanded-in { from { opacity: 0; transform: translateY(-2px); } }
@media (max-width: 700px) { .table-footer { grid-template-columns: 1fr auto; }.table-footer > label { display: none; }.expanded-row { padding-left: 12px; } }
</style>
