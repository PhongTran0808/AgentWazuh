# SKILL: RISK SCORING (KILL-CHAIN PRIORITY SCORE)

## NGUYÊN LÝ CHẤM ĐIỂM DUDETERMINISTIC
Tính toán điểm số từ 0 - 100 bằng Python lõi, tuyệt đối không phụ thuộc vào suy đoán LLM.

## CÔNG THỨC TRỌNG SỐ 5 THÀNH PHẦN
$$\text{Priority Score} = w_1 \cdot \text{BaseSeverity} + w_2 \cdot \text{MITREBonus} + w_3 \cdot \log_{10}(\text{Count}) + w_4 \cdot \text{AssetCriticality} + w_5 \cdot \text{KillChainStage}$$

1. $w_1$: Max rule level $\times 4.5$ (Tối đa 45 điểm).
2. $w_2$: MITRE Tactic Match (+20 điểm nếu có ánh xạ).
3. $w_3$: Logarithmic Frequency $\log_{10}(\text{Count}) \times 8$ (Tối đa 15 điểm).
4. $w_4$: Criticality Level $\times 2$ (Tối đa 10 điểm).
5. $w_5$: Kill-Chain Stage Bonus (+5 Recon, +10 Auth Fail, +15 Active Threat/Response Block).
