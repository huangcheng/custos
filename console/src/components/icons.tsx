import type { ReactNode, SVGProps } from "react";

// Hand-drawn 24-grid line icons (stroke 1.6, round caps): the console has no
// icon dependency and does not need one for a dozen glyphs.
type IconProps = Omit<SVGProps<SVGSVGElement>, "children"> & { size?: number };

function Icon({ size = 16, children, ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

export function IconItems(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="4" y="4" width="16" height="16" rx="3" />
      <circle cx="12" cy="12" r="3.5" />
      <path d="M12 8.5V6M12 18v-2.5M8.5 12H6M18 12h-2.5" />
    </Icon>
  );
}

export function IconKeys(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="8" cy="15.5" r="4" />
      <path d="M11 12.5 20 3.5M16 7.5l2.5 2.5M13.5 10l2 2" />
    </Icon>
  );
}

export function IconAudit(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 6h16M4 12h16M4 18h7" />
      <path d="M14 18l2 2 4-4" />
    </Icon>
  );
}

export function IconSettings(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 7h8M18 7h2M4 17h4M14 17h6" />
      <circle cx="15" cy="7" r="2.2" />
      <circle cx="11" cy="17" r="2.2" />
    </Icon>
  );
}

export function IconLogout(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M10 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3" />
      <path d="M15 8l4 4-4 4M19 12H10" />
    </Icon>
  );
}

export function IconClose(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6 6l12 12M18 6 6 18" />
    </Icon>
  );
}

export function IconCopy(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V6a2 2 0 0 1 2-2h9" />
    </Icon>
  );
}

export function IconCheck(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M5 12l5 5L20 7" />
    </Icon>
  );
}

export function IconChevron(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M9 6l6 6-6 6" />
    </Icon>
  );
}

export function IconShield(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6l-7-3Z" />
      <path d="M9 12l2 2 4-4" />
    </Icon>
  );
}
