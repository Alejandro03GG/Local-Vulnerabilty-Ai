# UI Quality Checklist

Use this checklist before finalizing a React + Tailwind + shadcn/ui interface.

## Product

- The page has a clear user and goal.
- The primary action is obvious.
- Secondary actions are lower emphasis.
- The first screen shows useful information, not decorative filler.
- Copy is domain-specific and realistic.

## Visual Quality

- No large decorative gradients.
- No random shadows.
- No fake icon clusters.
- No meaningless cards.
- No excessive border radius.
- No generic SaaS filler sections.
- Typography scale is restrained.
- Spacing is consistent.
- Alignment is precise.
- Surfaces use borders/backgrounds rather than decoration.

## States

- Default state implemented.
- Hover state implemented.
- Loading state implemented.
- Empty state implemented.
- Error state implemented.
- Disabled state implemented.
- Focus-visible state implemented.
- Mobile state implemented.
- Long content / overflow handled.
- Permission/read-only state considered when relevant.

## Responsive

- Mobile is not just a squeezed desktop.
- Toolbars wrap or stack.
- Tables become cards or scroll intentionally.
- Primary actions remain reachable.
- Tap targets are usable.
- Nonessential metadata is hidden only when still recoverable elsewhere.

## Accessibility

- Buttons use `<button>` or shadcn Button.
- Navigation uses links.
- Inputs have labels.
- Icon-only controls have `aria-label`.
- Tables have headers.
- Focus states are visible.
- Status is not color-only.
- Error messages are human-readable.

## Engineering

- Components are named by product role.
- Props are typed.
- No unnecessary `any`.
- Mock data is realistic.
- Edge cases are represented.
- Existing repo conventions are followed.
- Lint/typecheck/build are run when possible.
