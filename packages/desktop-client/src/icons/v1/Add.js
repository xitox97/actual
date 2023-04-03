import * as React from 'react';

const SvgAdd = props => (
  <svg
    {...props}
    viewBox="0 0 24 24"
    xmlns="http://www.w3.org/2000/svg"
    style={{
      color: '#242134',
      ...props.style,
    }}
  >
    <path
      fill="currentColor"
      className="path"
      d="M23 11.5a1.5 1.5 0 0 1-1.5 1.5h-20a1.5 1.5 0 0 1 0-3h20a1.5 1.5 0 0 1 1.5 1.5Z"
    />
    <path
      fill="currentColor"
      className="path"
      d="M11.5 23a1.5 1.5 0 0 1-1.5-1.5v-20a1.5 1.5 0 0 1 3 0v20a1.5 1.5 0 0 1-1.5 1.5Z"
    />
  </svg>
);

export default SvgAdd;