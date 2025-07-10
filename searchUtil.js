function parseBooleanExpression(query) {
  if (!query) return [];
  const groups = query.split(/\s+OR\s+/i).map(g => g.trim()).filter(Boolean);
  const result = [];
  for (const g of groups) {
    const words = g.split(/\s+/).filter(Boolean);
    const tokens = [];
    for (let i = 0; i < words.length; i++) {
      let w = words[i];
      if (/^OR$/i.test(w)) continue;
      let not = false;
      if (/^AND$/i.test(w)) continue;
      if (/^NOT$/i.test(w)) {
        not = true;
        i++;
        w = words[i];
        if (!w) break;
      }
      tokens.push({ term: w, not });
    }
    if (tokens.length) result.push(tokens);
  }
  return result;
}

function buildSearchClause(query, fields) {
  const groups = parseBooleanExpression(query);
  const params = [];
  const clauses = groups.map(tokens => {
    const parts = tokens.map(tok => {
      const like = fields.map(f => `${f} LIKE ?`).join(' OR ');
      params.push(...fields.map(() => `%${tok.term}%`));
      return tok.not ? `NOT (${like})` : `(${like})`;
    });
    return `(${parts.join(' AND ')})`;
  });
  return { clause: clauses.join(' OR '), params };
}

function matchesTagQuery(tags, query) {
  const groups = parseBooleanExpression(query);
  if (!groups.length) return true;
  return groups.some(tokens =>
    tokens.every(t => (t.not ? !tags.includes(t.term) : tags.includes(t.term)))
  );
}

module.exports = {
  parseBooleanExpression,
  buildSearchClause,
  matchesTagQuery
};
