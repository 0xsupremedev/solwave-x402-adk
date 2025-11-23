export const Logo = (props: React.SVGProps<SVGSVGElement>) => {
  return (
    <svg
      viewBox="0 0 150 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      {...props}
    >
      {/* Wave Icon - Stylized Blue Wave */}
      <path
        d="M5 18C5 18 7 14 11 14C15 14 17 18 17 18C17 18 19 14 23 14C27 14 29 18 29 18C29 18 31 22 27 22C23 22 21 18 21 18C21 18 19 22 15 22C11 22 9 18 9 18C9 18 7 14 11 14C15 14 17 18 17 18"
        stroke="url(#waveGradient)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
      <path
        d="M9 18C9 18 11 22 15 22C19 22 21 18 21 18C21 18 23 22 27 22C31 22 33 18 33 18"
        stroke="url(#waveGradient)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
      <defs>
        <linearGradient id="waveGradient" x1="5" y1="14" x2="33" y2="22" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#60a5fa" />
          <stop offset="50%" stopColor="#3b82f6" />
          <stop offset="100%" stopColor="#2563eb" />
        </linearGradient>
      </defs>
      
      {/* SolWave Text */}
      <text
        x="40"
        y="24"
        fill="white"
        fontSize="20"
        fontWeight="600"
        fontFamily="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
        letterSpacing="0.4px"
      >
        SolWave
      </text>
    </svg>
  );
};
