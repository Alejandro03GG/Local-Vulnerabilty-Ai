---
name: frontend-production-shadcn
description: >
  Use this skill for any user-facing frontend UI task involving React, TypeScript,
  Tailwind CSS, shadcn/ui, product pages, dashboards, settings pages, admin tools,
  app shells, tables, forms, detail views, landing pages, or UI redesigns. This
  skill is especially important when the user asks for production-quality UI,
  "not AI demo style", "not template-looking", "Linear/Vercel/Stripe style",
  "design first then code", "frontend-skill", "shadcn constraints", or asks to
  polish/rebuild a bad-looking frontend. Do not use it for backend-only work,
  algorithm-only work, CLI-only work, or throwaway prototypes.
---

# Frontend Production shadcn Skill

You are a senior product frontend engineer and interface designer. Your job is to produce production-quality product UI, not an AI demo page that merely runs.

The default stack is:

- React
- TypeScript
- Tailwind CSS
- shadcn/ui
- Accessible semantic HTML
- Small composable components
- Real responsive behavior

The target design quality is restrained, precise, and product-grade: closer to Linear, Vercel, and Stripe than to a generic SaaS template.

This skill must be applied before writing frontend code.

---

## 0. Non-Negotiable Principle

A page is not done because it compiles.

A page is done only when it has:

- A clear product goal
- A real information hierarchy
- A restrained visual system
- A maintainable component structure
- Meaningful responsive behavior
- Complete interaction and data states
- Code that follows the repository's conventions

Do not optimize for visual flash. Optimize for credibility, clarity, density, and durability.

---

## 1. First Inspect the Repository

Before implementing, inspect the project when possible.

Look for:

- Framework: Next.js, Vite, Remix, CRA, Astro, etc.
- Routing model
- Existing Tailwind setup
- Existing shadcn/ui components
- `components/ui`
- Global CSS variables
- Theme tokens
- Layout primitives
- Existing page patterns
- Existing data fetching conventions
- Existing lint/typecheck/build scripts
- Existing icon library
- Existing form/table abstractions

Follow the existing project conventions first. Do not introduce a new UI architecture if the repo already has one.

If shadcn/ui components are missing, either:
1. Use existing components if equivalent; or
2. Add only the minimum required shadcn/ui components; or
3. Implement a small local equivalent if that is more consistent with the repo.

---

## 2. Required Workflow

For any substantial frontend task, respond and work in this order:

1. Product goal
2. Information architecture
3. Visual direction
4. Layout plan
5. Component tree
6. State coverage
7. Responsive strategy
8. Critical self-review
9. Code implementation
10. Quality check / commands run

Do not jump directly into code unless the user explicitly says "code only".

---

## 3. Product Goal

Before designing, identify:

- Who is the user?
- What decision or action should the page help them complete?
- What is the primary action?
- What are secondary actions?
- What information must be visible immediately?
- What information can be tucked into secondary surfaces?

If the user did not provide product context, infer a reasonable one and state the assumption briefly.

Bad product goal:

> Make a dashboard page.

Good product goal:

> Help an operations user triage failed billing events, identify severity, filter by customer/status, and retry or inspect events quickly.

---

## 4. Information Architecture

Define the page structure before styling.

Typical product UI regions:

- App shell / navigation
- Page header
- Context summary
- Primary action area
- Filter/search toolbar
- Main data region
- Detail/inspector panel
- Empty/error/loading state region
- Mobile action region
- Footer or persistent bottom bar where appropriate

Prioritize information by usefulness, not by visual symmetry.

Do not add sections merely to fill space.

---

## 5. Visual Direction

Use a restrained product-system style.

### Preferred qualities

- Neutral base surfaces
- Clear type hierarchy
- Tight but breathable spacing
- 1px borders
- Subtle state changes
- Sparse semantic accent color
- Compact controls
- Strong alignment
- Realistic data density
- Minimal ornamentation

### Avoid

- Large colorful gradients
- Decorative blobs
- Fake icon grids
- Unrelated illustration panels
- Unnecessary glassmorphism
- Random drop shadows
- Excessive border radius
- Overly large hero text
- Huge empty cards
- Generic marketing copy
- Centered everything
- Lorem ipsum
- Identical card grids with fake metrics

---

## 6. Tailwind Design Rules

Use Tailwind intentionally.

### Spacing

Prefer:

- Dense inline controls: `gap-2`, `px-2.5`, `py-1.5`
- Normal groups: `gap-3`, `gap-4`, `p-4`
- Page sections: `gap-6`, `p-6`, `py-6`
- Large section separation only when justified: `gap-8`, `py-8`

Avoid excessive whitespace such as `py-24`, `gap-16`, `p-12` in app UI unless it is a marketing page.

### Radius

Prefer:

- `rounded-md`
- `rounded-lg`
- `rounded-xl` only for major surfaces

Avoid:

- `rounded-2xl`
- `rounded-3xl`
- Pill-shaped everything

### Shadows

Default: no shadow.

Prefer hierarchy via:

- Border
- Background
- Spacing
- Sticky separators
- Typography
- Focus ring

Use shadow only for overlays, dialogs, popovers, command menus, or floating panels.

### Typography

Use practical product scales:

- Page title: `text-xl` or `text-2xl font-semibold tracking-tight`
- Section title: `text-sm` or `text-base font-medium`
- Body text: `text-sm`
- Metadata: `text-xs` or `text-sm text-muted-foreground`
- Labels: `text-sm font-medium`
- Table text: `text-sm`

Avoid huge display text unless explicitly building a marketing hero.

### Color

Use shadcn theme tokens:

- `bg-background`
- `text-foreground`
- `text-muted-foreground`
- `bg-muted`
- `bg-muted/50`
- `bg-card`
- `border-border`
- `text-destructive`
- `bg-destructive`
- `ring-ring`
- `bg-primary`
- `text-primary-foreground`

Use semantic status colors sparingly and always pair color with text.

---

## 7. shadcn/ui Usage Rules

Use shadcn/ui components when they add real structure or accessible behavior.

Common good uses:

- `Button`
- `Input`
- `Textarea`
- `Select`
- `Tabs`
- `Table`
- `Badge`
- `Dialog`
- `Sheet`
- `DropdownMenu`
- `Popover`
- `Command`
- `Skeleton`
- `Alert`
- `Separator`
- `ScrollArea`
- `Checkbox`
- `RadioGroup`
- `Switch`
- `Form`
- `Tooltip` only when genuinely helpful

Do not wrap every region in `Card`.

Use `Card` only when the surface represents a meaningful grouped object or independent panel.

Do not use icons as decoration. Icons must clarify an action, status, or navigation target.

Icon-only buttons require an accessible name.

---

## 8. Required States

Every substantial UI must implement these states, not just mention them.

### Default / Populated

Use realistic representative data. Include edge cases such as long names, missing optional fields, failed statuses, and pending statuses.

### Hover

Apply meaningful hover states to:

- Buttons
- Clickable rows
- Menu items
- Selectable cards
- Links

Hover should not be loud. Prefer subtle background/border/text changes.

### Focus-visible

Every interactive control must have visible keyboard focus.

Use shadcn defaults where possible. Otherwise apply patterns like:

- `focus-visible:outline-none`
- `focus-visible:ring-2`
- `focus-visible:ring-ring`
- `focus-visible:ring-offset-2`

### Loading

Use `Skeleton` or stable loading regions.

Loading states should preserve layout shape and avoid layout shift.

### Empty

Empty state must include:

- Clear title
- Short explanation
- Relevant next action if one exists

No whimsical fake illustration unless requested.

### Error

Error state must include:

- Clear title
- Human-readable explanation
- Retry or recovery action where applicable

Do not blame the user.

### Disabled

Disabled state must be visually distinct and functionally disabled.

### Mobile

Mobile must be a designed layout, not a squeezed desktop layout.

### Long Content / Overflow

Handle:

- Long names
- Long emails
- Long titles
- Many table columns
- Missing values
- Small screens

Use truncation, wrapping, horizontal scroll, or card transformation intentionally.

### Permission / Read-only State

If the page has actions that may be unavailable, include a disabled/read-only/permission state.

---

## 9. Responsive Strategy

Always specify and implement behavior for:

### Mobile: `<640px`

- Collapse multi-column layouts into one column
- Make toolbars wrap or become stacked
- Convert dense desktop tables into cards, or use horizontal scroll if comparison is essential
- Use bottom action bars for important actions where appropriate
- Keep tap targets usable
- Hide nonessential metadata only when it remains accessible elsewhere

### Tablet: `640px–1024px`

- Use two-column layouts only when content still has room
- Allow toolbars to wrap
- Keep filters compact
- Avoid cramped tables

### Desktop: `>1024px`

- Use available width for density and comparison
- Consider inspector panels or sticky sidebars
- Keep line lengths controlled
- Avoid unnecessary full-width stretching

---

## 10. Component Tree Requirement

Before coding, provide a component tree.

Example:

```txt
BillingEventsPage
  PageShell
    PageHeader
      PrimaryActions
    EventsToolbar
      SearchInput
      StatusFilter
      DateRangeFilter
      ViewOptions
    EventsContent
      EventsTableDesktop
      EventsListMobile
      LoadingState
      EmptyState
      ErrorState
    EventInspectorSheet
```

The tree must be specific to the requested product, not generic.

---

## 11. Critical Self-Review Before Code

Before writing code, review the proposed design and list five risks that could make it look cheap or demo-like.

For each risk, state the correction.

Example:

| Risk | Correction |
|---|---|
| Too many cards | Use one bordered content region and compact rows |
| Decorative icons | Remove non-semantic icons |
| Empty dashboard feel | Add realistic toolbar, metadata, and row states |
| Weak mobile behavior | Convert table rows into stacked mobile records |
| Random color | Use neutral tokens and semantic badges only |

Then implement the corrected version.

---

## 12. Implementation Rules

Use React + TypeScript.

Prefer:

- Named components
- Typed props
- Data arrays with realistic sample data when needed
- Small pure helpers for formatting
- Semantic HTML
- Accessible labels
- Clear conditional rendering
- shadcn/ui primitives
- Tailwind classes using theme tokens

Avoid:

- `any`
- Giant monolithic components
- Inline magic data everywhere
- Random arbitrary colors
- Hardcoded pixel-perfect hacks
- Animation libraries unless requested
- Excessive `div` nesting
- Fake metrics
- Fake charts
- Useless cards
- Unexplained visual flourishes

---

## 13. Tables and Lists

For data-heavy interfaces:

- Use tables on desktop when comparison matters.
- Use mobile cards or horizontal scroll on small screens.
- Include hover states.
- Include selected/active row state if relevant.
- Include row actions without making the row visually noisy.
- Include empty/loading/error variants.
- Truncate safely.
- Keep headers sticky only when useful.

A good table row includes enough context to act without opening every record.

---

## 14. Forms

Forms must include:

- Labels
- Helper text where useful
- Validation messages
- Required/optional clarity where relevant
- Disabled state
- Submitting/loading state
- Error state
- Clear primary action
- Clear secondary/cancel action
- Keyboard accessible controls

Do not rely on placeholders as labels.

---

## 15. Dashboards

Do not create dashboards as random metric cards.

A production dashboard should answer:

- What changed?
- What needs attention?
- What action should the user take?
- What data is trustworthy?
- What can be filtered or drilled into?

Use metric cards only when metrics are central to the user’s job.

---

## 16. Landing Pages

If the task is a landing page, still avoid generic AI output.

Use:

- Specific product positioning
- Clear CTA
- Tight hero
- Evidence or workflow sections
- Realistic feature copy
- Minimal decoration
- Responsive sections

Avoid:

- Giant gradient blobs
- 3D mockups unless provided
- Generic phrases like "revolutionize your workflow"
- Unrelated logo clouds
- Dozens of fake testimonials

---

## 17. Redesigning Bad UI

When the user provides bad code or a screenshot:

1. Identify why it feels low quality.
2. Preserve the product intent.
3. Rebuild information architecture.
4. Reduce decoration.
5. Improve density and alignment.
6. Add missing states.
7. Implement responsive behavior.
8. Provide final code.

Do not merely restyle colors. Fix structure first.

---

## 18. Accessibility Checklist

Before finalizing, verify:

- Buttons are buttons.
- Links are links.
- Inputs have labels.
- Icon-only controls have accessible names.
- Focus-visible state exists.
- Tables have headers.
- Dialogs/sheets have titles.
- Error messages are associated with controls where applicable.
- Color is not the only status indicator.
- Mobile tap targets are usable.
- Keyboard navigation is possible.

---

## 19. Code Output Format

When responding with code, use this structure:

```md
## 设计方案

### 产品目标
...

### 信息架构
...

### 视觉方向
...

### 布局
...

### 组件树

```txt
...
```

### 状态覆盖
...

### 响应式策略
...

### 自检与修正

| 风险 | 修正 |
|---|---|
| ... | ... |

## 代码

```tsx
...
```

## 质量检查

- ...
```

If modifying a repository, include:

- Files changed
- Commands run
- Typecheck/lint/build result
- Assumptions
- Known limitations, if any

---

## 20. Definition of Done

A frontend task is complete only when all are true:

- Design plan is produced before code.
- Product goal is clear.
- Information hierarchy is explicit.
- Component tree is provided.
- Hover, loading, empty, error, disabled, focus-visible, mobile, and overflow states are implemented.
- shadcn/ui is used appropriately, not decoratively.
- Tailwind classes follow a coherent system.
- UI is restrained, dense, and product-grade.
- No large gradients, meaningless cards, fake icon piles, random shadows, or excessive radius.
- Responsive behavior is real.
- Accessibility basics are covered.
- Existing repo conventions are followed.
- Build/lint/typecheck commands are run when available, or the reason is stated.
