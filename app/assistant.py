"""AI Assistant : LLM via LangChain (si ANTHROPIC_API_KEY) sinon repli par règles."""
import os, json

def explain(findings, events) -> str:
    summary = json.dumps({"findings": findings[:6], "events": events[:5]}, ensure_ascii=False)
    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            from langchain_anthropic import ChatAnthropic
            from langchain_core.prompts import ChatPromptTemplate
            chain = ChatPromptTemplate.from_messages([
                ("system", "Tu es un expert en sécurité des routeurs domestiques. Réponds en français, clairement, pour un non-expert."),
                ("human", "Explique ces alertes et donne un plan d'action priorisé en 5 points max :\n{data}")
            ]) | ChatAnthropic(model=os.getenv("LLM_MODEL", "claude-sonnet-4-6"), max_tokens=700)
            return chain.invoke({"data": summary}).content
        except Exception as e:
            print("LLM indisponible, repli règles :", e)
    lines = ["Plan d'action prioritaire (mode hors-ligne) :"]
    lines += [f"{i}. [{f['severity']}] {f['title']} → {f['fix']}" for i, f in enumerate(findings[:5], 1)]
    if events: lines.append(f"{len(events)} flux suspects détectés ; vérifier les IP sources et les bloquer au pare-feu.")
    return "\n".join(lines)
