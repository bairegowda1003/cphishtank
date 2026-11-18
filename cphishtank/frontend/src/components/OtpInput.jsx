import { useRef } from "react";

export default function OtpInput({ value, onChange, disabled = false }) {
  const refs = useRef([]);
  const digits = Array.from({ length: 6 }, (_, index) => value[index] || "");

  function setAt(index, digit) {
    const next = digits.slice();
    next[index] = digit;
    onChange(next.join(""));
  }

  function paste(event, index) {
    const pasted = event.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
    if (!pasted) return;
    event.preventDefault();
    const next = digits.slice();
    [...pasted].forEach((digit, offset) => { if (index + offset < 6) next[index + offset] = digit; });
    onChange(next.join(""));
    refs.current[Math.min(index + pasted.length, 5)]?.focus();
  }

  return (
    <div className="otp-boxes" role="group" aria-label="Six-digit verification code">
      {digits.map((digit, index) => (
        <input
          key={index}
          ref={(element) => { refs.current[index] = element; }}
          aria-label={`Digit ${index + 1} of 6`}
          autoComplete={index === 0 ? "one-time-code" : "off"}
          autoFocus={index === 0}
          disabled={disabled}
          inputMode="numeric"
          maxLength={1}
          pattern="[0-9]"
          value={digit}
          onPaste={(event) => paste(event, index)}
          onChange={(event) => {
            const entered = event.target.value.replace(/\D/g, "").slice(-1);
            setAt(index, entered);
            if (entered && index < 5) refs.current[index + 1]?.focus();
          }}
          onKeyDown={(event) => {
            if (event.key === "Backspace" && !digits[index] && index > 0) refs.current[index - 1]?.focus();
            if (event.key === "ArrowLeft" && index > 0) refs.current[index - 1]?.focus();
            if (event.key === "ArrowRight" && index < 5) refs.current[index + 1]?.focus();
          }}
        />
      ))}
    </div>
  );
}
