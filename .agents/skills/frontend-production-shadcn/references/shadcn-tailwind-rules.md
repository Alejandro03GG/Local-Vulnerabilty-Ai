# shadcn/ui and Tailwind Constraints

## Use shadcn/ui for structure and accessibility

Good default components:

- Button
- Input
- Textarea
- Select
- Tabs
- Table
- Badge
- Dialog
- Sheet
- DropdownMenu
- Popover
- Command
- Skeleton
- Alert
- Separator
- ScrollArea
- Checkbox
- RadioGroup
- Switch
- Form

## Avoid decorative misuse

- Do not wrap everything in Card.
- Do not use Tooltip for obvious labels.
- Do not use Dialog when Sheet or inline editing is better.
- Do not use icons just to make the UI feel busy.
- Do not add visual effects without product purpose.

## Preferred Tailwind tokens

Use theme-aware classes:

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

## Preferred sizing

- Page title: `text-xl` or `text-2xl font-semibold tracking-tight`
- Section title: `text-sm` or `text-base font-medium`
- Body: `text-sm`
- Metadata: `text-xs` or `text-sm text-muted-foreground`
- Dense controls: `h-8`, `h-9`
- Standard controls: `h-9`, `h-10`

## Preferred surfaces

- Use `border` and `bg-background`.
- Use `bg-muted/50` for subtle nested regions.
- Use sticky borders for headers/toolbars.
- Use shadow only for overlays.
