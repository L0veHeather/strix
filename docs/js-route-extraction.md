# JS Route Extraction Feature

## Status: ✅ Implemented (Prompt Module)

## Files Created/Modified

### 1. New Prompt Module
- **File**: `strix/prompts/reconnaissance/js_route_extraction.jinja`
- **Purpose**: Comprehensive guide for extracting API routes from JavaScript files
- **Features**:
  - Regex patterns for route extraction
  - Framework-specific guidance (React, Vue, Angular, Next.js, Express)
  - Path construction logic
  - Validation methodology
  - Integration workflow

### 2. Updated Root Agent
- **File**: `strix/prompts/coordination/root_agent.jinja`
- **Changes**: Added reconnaissance priorities for JS route extraction
- **Impact**: Root agent will now prioritize JS analysis during reconnaissance

## Usage

### For Agents
Agents can now automatically:
1. Identify and download JavaScript files from targets
2. Extract API routes using provided regex patterns
3. Construct full URLs from base URLs and relative paths
4. Validate discovered endpoints
5. Feed routes to vulnerability testing modules

### Example Workflow
```
1. Root agent creates reconnaissance agent
2. Recon agent downloads main.js, app.js, etc.
3. Agent applies js_route_extraction patterns
4. Discovers: /api/users, /gateway/user-service/profile, /graphql
5. Validates routes (OPTIONS/HEAD requests)
6. Creates specialized testing agents for each route type
```

## Supported Frameworks
- ✅ React Router
- ✅ Vue Router
- ✅ Angular Router
- ✅ Next.js (App & Pages Router)
- ✅ Express.js
- ✅ Generic REST APIs
- ✅ GraphQL
- ✅ WebSocket endpoints

## Next Steps (Optional)

### Phase 2: Tool Development
If you need more automation, we can implement:
- Python tool for automated JS parsing
- Regex-based route extractor
- URL constructor utility
- Endpoint validator

### Phase 3: Integration
- Add to default reconnaissance workflow
- Create dedicated JS analysis agent type
- Integrate with vulnerability testing pipeline

## Testing

To test the feature:
```bash
# Run Strix against a web application
strix scan https://example.com

# The agent will now automatically:
# 1. Download JS files
# 2. Extract routes
# 3. Test discovered endpoints
```

## Documentation
- Implementation plan: `js-route-extraction-plan.md`
- Prompt module: `strix/prompts/reconnaissance/js_route_extraction.jinja`
